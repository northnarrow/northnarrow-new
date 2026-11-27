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

/// Lot 2.2: the pinned one-slot array the agent sets to
/// [`EXEC_MARKS_ARMED_ON`] once it has written the marks: before that the
/// mapping hooks judge nothing (an empty map would take every role away).
pub const EXEC_MARKS_ARMED_MAP_NAME: &str = "EXEC_MARK_ARMED";
/// [`EXEC_MARKS_ARMED_MAP_NAME`]'s value once the marks are written.
pub const EXEC_MARKS_ARMED_ON: u32 = 1;

/// Lot 2.2: the pinned map of the processes that lost their role — a
/// process running the agent's or the watchdog's binary, or holding a role,
/// that mapped executable code from an image without [`MARK_ROLE`] (or
/// anonymous memory). Keyed by tgid, valued by its start; written by the
/// mapping hooks only (frozen at its creation: no descriptor writes it, the
/// agent's included), its entry removed at the process's exit. Such a
/// process is protected as a target, exempt from nothing, and never takes
/// a vacant role.
pub const ROLE_UNMARKED_MAP_NAME: &str = "ROLE_UNMARKED";
/// Its capacity: the processes that run our binaries are a handful; a full
/// map leaves the role to a process it cannot record, so the hook also
/// signs that (the record is never lost with the entry).
pub const ROLE_UNMARKED_MAX: u32 = 64;

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

/// Lot 2.2 (the watchdog's slot, A2): whether a successor may take the
/// agent's vacated role. Once the watchdog says it arms the slot
/// (`arm_supported`, lot 2.5 writes it), the vacated agent slot opens only
/// while the live watchdog's arm is fresh (`arm_deadline_ns` after
/// `now_ns`); with no live watchdog (`watchdog_live` false: its slot vacant
/// too) nothing can arm it, and the successor's own test decides (the
/// fallback). Before the watchdog supports it, nothing changes.
#[inline(always)]
pub const fn agent_slot_open(
    arm_supported: bool,
    watchdog_live: bool,
    arm_deadline_ns: u64,
    now_ns: u64,
) -> bool {
    !arm_supported || !watchdog_live || now_ns < arm_deadline_ns
}

/// Lot 2.2: the pinned two-slot array of the watchdog's arm: slot
/// [`ARM_SLOT_SUPPORTED`] 1 once the watchdog arms the agent's slot (lot
/// 2.5), slot [`ARM_SLOT_DEADLINE`] the arm's `CLOCK_BOOTTIME` deadline.
pub const WATCHDOG_ARM_MAP_NAME: &str = "WATCHDOG_ARM";
pub const ARM_SLOT_SUPPORTED: u32 = 0;
pub const ARM_SLOT_DEADLINE: u32 = 1;
/// The longest arm the hook honours (the watchdog's respawn is quick).
pub const ARM_MAX_NS: u64 = 30_000_000_000;

#[cfg(test)]
mod tests {
    use super::*;

    /// Lot 2.2: the agent's vacated slot opens with a fresh arm of a live
    /// watchdog, or with no live watchdog (the fallback), or before the
    /// watchdog supports the arm; never with a stale arm of a live one.
    #[test]
    fn the_agent_slot_needs_the_live_watchdog_s_arm() {
        assert!(agent_slot_open(false, true, 0, 100), "not supported yet");
        assert!(agent_slot_open(true, false, 0, 100), "both vacant");
        assert!(agent_slot_open(true, true, 101, 100), "armed");
        assert!(!agent_slot_open(true, true, 100, 100), "the arm expired");
        assert!(!agent_slot_open(true, true, 0, 100), "never armed");
        const { assert!(ARM_MAX_NS <= 60_000_000_000) };
        assert_ne!(ARM_SLOT_SUPPORTED, ARM_SLOT_DEADLINE);
    }

    #[test]
    fn the_map_names_are_distinct() {
        let names = [
            EXEC_MARKS_MAP_NAME,
            EXEC_MARKS_ARMED_MAP_NAME,
            ROLE_UNMARKED_MAP_NAME,
            WATCHDOG_ARM_MAP_NAME,
        ];
        for (i, a) in names.iter().enumerate() {
            assert!(
                a.len() < 16,
                "{a}: the kernel keeps 15 bytes of a map's name"
            );
            for b in &names[i + 1..] {
                assert_ne!(a, b);
            }
        }
        const { assert!(ROLE_UNMARKED_MAX >= 8) };
    }

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
