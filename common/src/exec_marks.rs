//! Lot 2.1 (S2 scaffold): the per-inode marks of executable images.
//!
//! One pinned map, keyed by the kernel's `(dev, ino)` of a file
//! ([`crate::wire::InodeKey`], as `mm->exe_file` and a mapping's file give
//! it), whose value is a word of marks. No program reads or writes it yet:
//! the scaffold fixes its name, its bounds and the meaning of its bits
//! before the lots that use it.
//!
//! - [`MARK_ROLE`] (lot 2.2): an image the release starts a role
//!   process from — the agent's or the watchdog's binary, its dynamic
//!   loader, a library it links — registered by the agent from the files
//!   it verified. A process that claims a role while an executable mapping
//!   of an inode WITHOUT this mark is in it is refused the role and
//!   signed (`started_for_the_role` asks for "no unmarked mapping").
//! - [`MARKS_RESERVED_S12`]: the code-origin marks of stage S12 (an image
//!   written by an exposed lineage, owned by a signed package, on the
//!   signed exec list, a JIT library). Reserved: nothing sets them, and a
//!   reader takes a word with any of them set as one it does not know.
//!
//! The marks describe the file, never a path: a rename keeps them, a new
//! file at the same path has none. A file rewritten in place keeps its
//! inode; the lots that set [`MARK_ROLE`] clear it on any write-open of the
//! inode (the image the agent verified is gone).
//!
//! Shared by the eBPF programs and the agent. NOT `std`-gated.

/// The pinned map's name (by name, as `PROTECTED_INODES`: a restarted
/// agent registers into the map its pinned hooks read).
pub const EXEC_MARKS_MAP_NAME: &str = "EXEC_MARKS";

/// The map's capacity. A role's images are a handful (two binaries, the
/// loader, the C library and a few more each, in two spellings of a
/// merged `/usr`); S12 sizes its own use when it lands.
pub const EXEC_MARKS_MAX: u32 = 256;

/// The image is one the release starts a role process from (lot 2.2).
pub const MARK_ROLE: u32 = 1 << 0;

/// Bits 1 to 7: free for stage S2's lots. None is defined.
pub const MARKS_S2_FREE: u32 = 0x0000_00fe;

/// Bits 8 to 15: reserved for stage S12's code-origin marks.
pub const MARKS_RESERVED_S12: u32 = 0x0000_ff00;

/// Every bit this build gives a meaning to.
pub const MARKS_KNOWN: u32 = MARK_ROLE;

/// Whether an executable mapping of an inode whose marks are `marks`
/// (`None`: the inode is not in the map) keeps a process from its role: an
/// image that is not one of the release's role images. Pure, so that the
/// hook's decision is tested once, here (lot 2.2 calls it).
#[inline(always)]
pub const fn unmarked_for_role(marks: Option<u32>) -> bool {
    match marks {
        Some(m) => m & MARK_ROLE == 0,
        None => true,
    }
}

/// Whether `marks` carries a bit this build gives no meaning to (a word
/// written by a newer agent, or by S12's lots): its reader then takes only
/// the bits it knows, and says so where it reports the word.
#[inline(always)]
pub const fn has_unknown_marks(marks: u32) -> bool {
    marks & !MARKS_KNOWN != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mark_ranges_do_not_overlap() {
        assert_eq!(MARK_ROLE & MARKS_S2_FREE, 0);
        assert_eq!(MARK_ROLE & MARKS_RESERVED_S12, 0);
        assert_eq!(MARKS_S2_FREE & MARKS_RESERVED_S12, 0);
        assert_eq!(MARKS_KNOWN & MARKS_RESERVED_S12, 0);
        // bits 0 to 15 are given out, 16 to 31 are not
        assert_eq!(MARK_ROLE | MARKS_S2_FREE | MARKS_RESERVED_S12, 0xffff);
        const { assert!(EXEC_MARKS_MAX >= 16 && EXEC_MARKS_MAX <= 4096) };
    }

    /// An image not in the map, or in it without the role mark (an S12
    /// mark alone), keeps a process from its role; the role mark, with
    /// anything else, does not.
    #[test]
    fn only_the_role_mark_lets_a_mapping_through() {
        assert!(unmarked_for_role(None));
        assert!(unmarked_for_role(Some(0)));
        assert!(unmarked_for_role(Some(1 << 8)));
        assert!(unmarked_for_role(Some(MARKS_S2_FREE)));
        assert!(!unmarked_for_role(Some(MARK_ROLE)));
        assert!(!unmarked_for_role(Some(MARK_ROLE | (1 << 9))));
    }

    #[test]
    fn a_reserved_mark_is_unknown_to_this_build() {
        assert!(!has_unknown_marks(0));
        assert!(!has_unknown_marks(MARK_ROLE));
        assert!(has_unknown_marks(1 << 8));
        assert!(has_unknown_marks(1 << 1));
        assert!(has_unknown_marks(1 << 31));
    }
}
