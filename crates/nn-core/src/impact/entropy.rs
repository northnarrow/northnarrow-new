//! Lab PR 225: is what a burst left behind ciphertext? The entropy signal
//! of the ransomware combination: what a sampling found ([`Sample`]), what
//! samples ([`Sampler`]), the bounds of a sampling, the measure
//! ([`entropy_bits`]) and the formats high in entropy by design
//! ([`known_container`]).
//!
//! A block is **ciphertext-like** when its Shannon entropy is at least
//! [`HIGH_ENTROPY_BITS`] bits per byte and the file's start carries no known
//! container signature: compressed, media, database, image, package and
//! encrypted-container formats are high entropy by design. The signal holds
//! when at least [`HIGH_FILES_MIN`] of the files sampled are.
//!
//! R08b (lab PR 251): cut verbatim from the agent's `impact::entropy`, which
//! re-exports it and keeps the sampler of the host's files (`FsSampler`:
//! the reads without following a link or blocking, the owners and mode
//! bits, the host's view through `/proc/1/root`); the tracker gets it from
//! its host.

use std::time::Duration;

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
    /// ([`sample_copies_dir`]), never the originals beside them. The burst's
    /// uid is not known here: in a shared directory no copy counts.
    fn sample_copies(&self, copy: &str, suffix: &str, since: Duration) -> Sample;
    /// [`Self::sample_copies`] for a burst that ran as `uid` (lab PR 238):
    /// in a shared directory ([`shared_dir`]: `/tmp`, `/var/tmp`,
    /// `/dev/shm`) only the copies `uid` owns count. What the tracker calls.
    /// A sampler that answers by path (the tests', the golden replay's)
    /// keeps this default: its [`Self::sample_copies`].
    fn sample_copies_by(&self, copy: &str, suffix: &str, uid: u32, since: Duration) -> Sample {
        let _ = uid;
        self.sample_copies(copy, suffix, since)
    }
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
}
