//! What "the same file" means in the copy-on-first-write guard — and the
//! one place of `cow/` that compares inode numbers.
//!
//! Lot 315 (external bug hunt, editions 1.2/1.3/1.4, family F6; the
//! triage's N2 and BUG-110): a file is its device, its inode number and,
//! where the filesystem records it, its birth time (`statx`
//! `STATX_BTIME`). An inode number is freed when the file's last link and
//! descriptor go, and the next file created gets it (ext4 hands out the
//! lowest free number of its group): a new file of the owner's that
//! inherited the number of a file the attack deleted is another file. The
//! guard compared the device and the inode number alone in five places: the
//! restore moved such a new file into the journal's `evidence/` as "the
//! attack's renamed copy", where the expiry deleted it (N2: data loss);
//! `pick` merged two files into one entry and dropped the second without a
//! row (BUG-110); a writer's copy of the old file stood for the new one
//! (no copy taken); the new file's write-opens counted as the old one's.
//!
//! Each comparison asks one of three questions, and each errs on the side
//! that loses nothing:
//!
//! - [`FileId::may_be`]: the same device and inode number, and the same
//!   birth time where both are known. Asked where a wrong "yes" is the
//!   careful answer: a writer of the file still running skips its restore,
//!   a write-open after the copy keeps both, a file with the number is
//!   reported (never moved) when no birth time can be compared.
//! - `==`: the same identity as recorded (two unknown birth times are
//!   equal: a filesystem that records none). Asked where a wrong "no" is
//!   the careful answer: a writer's copy of the file is taken anew rather
//!   than taken for done, a copy is shared by the same file only, a restore
//!   refuses a file that changed under it; and to group a restore's entries
//!   (one per file: an entry without a birth time joins the others only
//!   when they are one file — `pick`).
//! - [`FileId::surely_is`]: both birth times known and equal. Asked before
//!   an act that loses a file when it is wrong: moving a file out of the
//!   owner's directory into the journal's evidence, and writing the
//!   original over the file at the path (rule 5 of the restore: after the
//!   review of #542, F2 — with `may_be` there, a new file of the owner's
//!   that inherited the number at the same path, on a filesystem without
//!   birth times, was restored in place over).
//!
//! `xtask/tests/cow_file_identity.rs` keeps it so: no other file of
//! `agent/src/cow/` compares an inode number or builds a key of one.

/// A file: device, inode number, birth time (ns) where recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId {
    pub dev: u64,
    pub ino: u64,
    pub btime_ns: Option<i64>,
}

/// Where the index files a file's entries: its device and inode number. A
/// slot is a place to look, never an identity — the entries found there
/// are compared with [`FileId`]'s questions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Slot {
    dev: u64,
    ino: u64,
}

impl FileId {
    pub const fn new(dev: u64, ino: u64, btime_ns: Option<i64>) -> Self {
        Self { dev, ino, btime_ns }
    }

    /// The index slot of this file.
    pub const fn slot(&self) -> Slot {
        Slot {
            dev: self.dev,
            ino: self.ino,
        }
    }

    /// The same device and inode number.
    const fn same_number(&self, other: &FileId) -> bool {
        self.dev == other.dev && self.ino == other.ino
    }

    /// Possibly the same file: the same device and inode number, and the
    /// same birth time where both are known.
    pub fn may_be(&self, other: &FileId) -> bool {
        self.same_number(other)
            && match (self.btime_ns, other.btime_ns) {
                (Some(a), Some(b)) => a == b,
                _ => true,
            }
    }

    /// Known to be the same file: the same device and inode number, and
    /// both birth times known and equal.
    pub fn surely_is(&self, other: &FileId) -> bool {
        self.same_number(other) && self.btime_ns.is_some() && self.btime_ns == other.btime_ns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: FileId = FileId::new(8, 5, Some(100));

    #[test]
    fn the_three_questions() {
        let reborn = FileId::new(8, 5, Some(200));
        let unknown = FileId::new(8, 5, None);
        let other_ino = FileId::new(8, 6, Some(100));
        let other_dev = FileId::new(9, 5, Some(100));
        // may_be: a birth time known on both sides decides; unknown, the number
        assert!(A.may_be(&A));
        assert!(!A.may_be(&reborn) && !reborn.may_be(&A));
        assert!(A.may_be(&unknown) && unknown.may_be(&A) && unknown.may_be(&unknown));
        assert!(!A.may_be(&other_ino) && !A.may_be(&other_dev));
        // ==: the identity as recorded, two unknowns equal
        assert_eq!(A, A);
        assert_ne!(A, reborn);
        assert_ne!(A, unknown);
        assert_eq!(unknown, FileId::new(8, 5, None));
        assert_ne!(A, other_ino);
        assert_ne!(A, other_dev);
        // surely_is: both known and equal
        assert!(A.surely_is(&A));
        assert!(!A.surely_is(&reborn));
        assert!(!A.surely_is(&unknown) && !unknown.surely_is(&A));
        assert!(!unknown.surely_is(&unknown));
        assert!(!A.surely_is(&other_ino) && !A.surely_is(&other_dev));
    }

    #[test]
    fn a_slot_is_the_number_only() {
        assert_eq!(A.slot(), FileId::new(8, 5, Some(200)).slot());
        assert_eq!(A.slot(), FileId::new(8, 5, None).slot());
        assert_ne!(A.slot(), FileId::new(8, 6, Some(100)).slot());
        assert_ne!(A.slot(), FileId::new(9, 5, Some(100)).slot());
    }
}
