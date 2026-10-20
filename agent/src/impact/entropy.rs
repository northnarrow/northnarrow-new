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

use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// Bytes of one sampled block.
pub const BLOCK: usize = 4096;
/// Bits per byte from which a block is ciphertext-like. Random bytes give
/// about 7.95 for a 4 KiB block, deflate and zstd output 7.9 and up; text
/// gives 4 to 5.5, executables 5 to 6.5.
pub const HIGH_ENTROPY_BITS: f64 = 7.5;
/// Files sampled per burst.
pub const SAMPLE_FILES_MAX: usize = 4;
/// Ciphertext-like files among them for the signal.
pub const HIGH_FILES_MIN: u32 = 2;
/// Directory entries looked at for siblings.
pub const DIR_SCAN_MAX: usize = 256;
/// Directory entries looked at for the copies of a copy-delete burst
/// ([`sample_copies_dir`]): only a name ending in the copies' suffix is
/// read further, so a directory of thousands of originals that still wait
/// their turn costs a few `getdents` calls.
pub const COPY_SCAN_MAX: usize = 4096;

/// What one sampling found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sample {
    /// Files read.
    pub examined: u32,
    /// Of those, ciphertext-like.
    pub high: u32,
    /// A file whose start carried a known container signature.
    pub containers: u32,
}

impl Sample {
    /// The entropy signal ([`HIGH_FILES_MIN`]).
    pub fn holds(&self) -> bool {
        self.high >= HIGH_FILES_MIN
    }
}

/// Samples the files a burst left behind. A trait so the tracker's tests
/// give it fixed answers.
pub trait Sampler: Send + Sync {
    /// Sample `path` and the files beside it changed since `since`.
    fn sample(&self, path: &str, since: Duration) -> Sample;
    /// Sample the copies a copy-delete burst left behind: `copy` (an
    /// original's name with `.suffix` appended, the original deleted) and
    /// the other copies of that shape changed since `since`
    /// ([`sample_copies_dir`]), never the originals beside them.
    fn sample_copies(&self, copy: &str, suffix: &str, since: Duration) -> Sample;
}

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
            sample_copies_dir(Path::new(copy), suffix, since, &host_view)
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
    let mut files: Vec<PathBuf> = vec![path.to_path_buf()];
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
                    files.push(name);
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
/// tree of small directories); at most [`COPY_SCAN_MAX`] entries looked at
/// in all, each reached through `host`.
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
    since: Duration,
    host: &dyn Fn(&Path) -> PathBuf,
) -> Sample {
    let mut files: Vec<PathBuf> = vec![copy.to_path_buf()];
    let (Some(dir), false) = (copy.parent(), suffix.is_empty()) else {
        return examine(files, host);
    };
    let mut scan = CopyScan {
        skip: copy,
        dot_suffix: format!(".{suffix}"),
        cutoff: SystemTime::now().checked_sub(since),
        host,
        budget: COPY_SCAN_MAX,
    };
    // Below it and beside it — never under the root (`/proc`, `/sys`,
    // `/dev` are no tree an encryptor walks).
    let mut below: Vec<PathBuf> = Vec::new();
    let below_wanted = dir.parent().is_some();
    scan.dir(dir, &mut files, below_wanted.then_some(&mut below));
    if files.len() < SAMPLE_FILES_MAX {
        let mut beside: Vec<PathBuf> = Vec::new();
        if let Some(parent) = dir.parent().filter(|p| p.parent().is_some()) {
            scan.dir(parent, &mut files, Some(&mut beside));
        }
        for d in below
            .iter()
            .chain(beside.iter().filter(|d| d.as_path() != dir))
        {
            if files.len() >= SAMPLE_FILES_MAX || scan.budget == 0 {
                break;
            }
            scan.dir(d, &mut files, None);
        }
    }
    examine(files, host)
}

/// The walk of [`sample_copies_dir`].
struct CopyScan<'a> {
    skip: &'a Path,
    dot_suffix: String,
    cutoff: Option<SystemTime>,
    host: &'a dyn Fn(&Path) -> PathBuf,
    /// Entries left to look at.
    budget: usize,
}

impl CopyScan<'_> {
    /// The copies in `dir` into `files` (up to twice [`SAMPLE_FILES_MAX`]:
    /// some may not be readable), its subdirectories into `subdirs`.
    fn dir(
        &mut self,
        dir: &Path,
        files: &mut Vec<PathBuf>,
        mut subdirs: Option<&mut Vec<PathBuf>>,
    ) {
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
            // Its original is gone: a copy still waiting for its deletion
            // (or a `.bak` kept beside its file) is not one.
            let gone = matches!(
                std::fs::symlink_metadata((self.host)(&dir.join(stem))),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound
            );
            if gone {
                files.push(name);
            }
        }
    }
}

/// Read up to [`SAMPLE_FILES_MAX`] of `files`, in order.
fn examine(files: Vec<PathBuf>, host: &dyn Fn(&Path) -> PathBuf) -> Sample {
    let mut out = Sample::default();
    for f in files {
        if out.examined as usize >= SAMPLE_FILES_MAX {
            break;
        }
        match classify(&host(&f)) {
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

/// One file: `None` when it cannot be read or is no regular file of at
/// least a block.
fn classify(path: &Path) -> Option<Kind> {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .ok()?;
    let meta = f.metadata().ok()?;
    if !meta.is_file() || meta.size() < BLOCK as u64 {
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

/// Shannon entropy of `bytes`, in bits per byte (0 for an empty slice).
pub fn entropy_bits(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in bytes {
        counts[*b as usize] += 1;
    }
    let n = bytes.len() as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

/// Signatures at the start of formats that are high entropy by design.
const SIGNATURES: &[&[u8]] = &[
    b"\x1f\x8b",                         // gzip
    b"BZh",                              // bzip2
    b"\xfd7zXZ\x00",                     // xz
    b"\x28\xb5\x2f\xfd",                 // zstd
    b"\x04\x22\x4d\x18",                 // lz4
    b"PK\x03\x04",                       // zip, docx, xlsx, jar, odt
    b"PK\x05\x06",                       // empty zip
    b"PK\x07\x08",                       // spanned zip
    b"7z\xbc\xaf\x27\x1c",               // 7-Zip
    b"Rar!\x1a\x07",                     // RAR
    b"\x89PNG",                          // PNG
    b"\xff\xd8\xff",                     // JPEG
    b"GIF8",                             // GIF
    b"RIFF",                             // WebP, WAV, AVI
    b"\x1a\x45\xdf\xa3",                 // Matroska, WebM
    b"OggS",                             // Ogg
    b"fLaC",                             // FLAC
    b"ID3",                              // MP3
    b"%PDF",                             // PDF
    b"wOFF",                             // WOFF
    b"wOF2",                             // WOFF2
    b"SQLite format 3\x00",              // SQLite
    b"\x37\x7f\x06\x82",                 // SQLite WAL
    b"\x37\x7f\x06\x83",                 // SQLite WAL
    b"QFI\xfb",                          // qcow2
    b"LUKS\xba\xbe",                     // LUKS
    b"\x7fELF",                          // ELF
    b"-----BEGIN ",                      // PEM, armored OpenPGP
    b"age-encryption.org/",              // age
    b"\x00GITCRYPT\x00",                 // git-crypt
    b"BORG_SEG",                         // borg segment
    b"mozLz40\x00",                      // Firefox session store
    b"\x30\x5c\x72\xa7\x1b\x6d\xfb\xfc", // Chromium simple cache
    b"070707",                           // cpio
    b"070701",                           // cpio (newc)
    b"hsqs",                             // squashfs
    b"\xca\xfe\xba\xbe",                 // Java class, Mach-O fat
    b"!<arch>",                          // ar, .deb
    b"\xed\xab\xee\xdb",                 // RPM
    b"\x00\x00\x01\xba",                 // MPEG-PS
    b"\x78\x01",                         // zlib
    b"\x78\x5e",                         // zlib
    b"\x78\x9c",                         // zlib
    b"\x78\xda",                         // zlib
    b"\x85\x01",                         // OpenPGP public-key encrypted session key
    b"\x85\x02",                         // OpenPGP
    b"\x84\x5e",                         // OpenPGP
    b"\x8c\x0d",                         // OpenPGP symmetric session key
    b"\xc1",                             // OpenPGP (new format)
    b"\xc3",                             // OpenPGP (new format)
];

/// A known container signature at the start of `head` (an MP4/MOV/HEIC
/// `ftyp` box at offset 4, a tar `ustar` header at offset 257 included).
pub fn known_container(head: &[u8]) -> bool {
    SIGNATURES.iter().any(|s| head.starts_with(s))
        || head.get(4..8) == Some(b"ftyp".as_slice())
        || head.get(257..262) == Some(b"ustar".as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn entropy_tells_ciphertext_from_text() {
        assert!(entropy_bits(&random(BLOCK, 7)) > 7.9);
        let text = "Quarterly figures: revenue rose 4% on the year. ".repeat(100);
        assert!(entropy_bits(text.as_bytes()) < 5.0);
        assert_eq!(entropy_bits(&[]), 0.0);
        assert_eq!(entropy_bits(&[0u8; BLOCK]), 0.0);
    }

    #[test]
    fn containers_are_recognised() {
        let mut gz = random(BLOCK, 3);
        gz[..2].copy_from_slice(b"\x1f\x8b");
        assert!(known_container(&gz));
        let mut mp4 = random(BLOCK, 4);
        mp4[4..8].copy_from_slice(b"ftyp");
        assert!(known_container(&mp4));
        let mut tar = vec![0u8; BLOCK];
        tar[257..262].copy_from_slice(b"ustar");
        assert!(known_container(&tar));
        let mut plain = random(BLOCK, 5);
        plain[0] = 0x42;
        assert!(!known_container(&plain));
    }

    /// The file a burst names and its recently changed siblings: random
    /// bytes hold the signal, text, a gzip archive and small files do not.
    #[test]
    fn sample_dir_counts_ciphertext_like_siblings() {
        let t = tempfile::TempDir::new().unwrap();
        let host = |p: &Path| p.to_path_buf();
        let d = t.path();
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

        let t2 = tempfile::TempDir::new().unwrap();
        let d2 = t2.path();
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
        let t = tempfile::TempDir::new().unwrap();
        let p = t.path().join("big.db");
        let mut b = "header text ".repeat(BLOCK).into_bytes();
        b.truncate(8 * BLOCK);
        let mid = 4 * BLOCK;
        b[mid..mid + BLOCK].copy_from_slice(&random(BLOCK, 21));
        std::fs::write(&p, &b).unwrap();
        assert_eq!(classify(&p), Some(Kind::Ciphertext));
    }

    /// Lab MS-23 copy-delete: the copies are sampled — the files named
    /// `<original>.<suffix>` whose original is gone — never the plain
    /// originals beside them, however many and however fresh; a copy whose
    /// original is still there, a small one and one of another suffix are
    /// not copies of the burst.
    #[test]
    fn sample_copies_reads_the_copies_not_the_originals() {
        let t = tempfile::TempDir::new().unwrap();
        let host = |p: &Path| p.to_path_buf();
        let d = t.path();
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
            Duration::from_secs(120),
            &host,
        );
        assert_eq!((s.examined, s.high), (3, 3), "{s:?}");
        assert!(s.holds());

        // Compressed copies (a rotation with compression) are containers.
        let t2 = tempfile::TempDir::new().unwrap();
        let d2 = t2.path();
        for i in 0..6 {
            let mut gz = random(2 * BLOCK, 30 + i);
            gz[..2].copy_from_slice(b"\x1f\x8b");
            std::fs::write(d2.join(format!("app{i}.log.1.gz")), gz).unwrap();
        }
        let s = sample_copies_dir(
            &d2.join("app5.log.1.gz"),
            "gz",
            Duration::from_secs(120),
            &host,
        );
        assert_eq!((s.examined, s.high, s.containers), (4, 0, 4), "{s:?}");
        // No suffix: the copy alone.
        let s = sample_copies_dir(
            &d.join("r902.txt.locked"),
            "",
            Duration::from_secs(120),
            &host,
        );
        assert_eq!((s.examined, s.high), (1, 1));
    }

    /// One original per directory: the copies are looked for below the
    /// copy's directory and beside it, within the scan's bound.
    #[test]
    fn sample_copies_looks_below_and_beside_in_small_directories() {
        let t = tempfile::TempDir::new().unwrap();
        let host = |p: &Path| p.to_path_buf();
        let top = t.path().join("home");
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
            Duration::from_secs(120),
            &host,
        );
        assert_eq!((s.examined, s.high), (4, 4), "{s:?}");
        // Nothing beside or below: the copy alone, one file, no signal.
        let lone = tempfile::TempDir::new().unwrap();
        let p = lone.path().join("x/only.pdf.crypt");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let mut b = random(BLOCK, 60);
        b[0] = 0x42;
        std::fs::write(&p, &b).unwrap();
        let s = sample_copies_dir(&p, "crypt", Duration::from_secs(120), &host);
        assert_eq!((s.examined, s.high), (1, 1));
        assert!(!s.holds());
    }
}
