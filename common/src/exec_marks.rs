//! Lot 2.1 (S2 scaffold): the per-inode marks of executable images.
//!
//! One pinned map, keyed by the kernel's `(dev, ino)` of a file
//! ([`crate::wire::InodeKey`], as `mm->exe_file` and a mapping's file give
//! it), whose value is a word of marks. No program reads or writes it yet:
//! the scaffold fixes its name, its bounds and the meaning of its bits
//! before the lots that use it.
//!
//! - [`MARK_ROLE`] (lot 2.2): the MAIN image of a role process — the
//!   agent's or the watchdog's binary, as the install or the upgrade put
//!   it in place inside a window — registered by the agent from the files
//!   it verified (decision D10 of the review of #644). Every other
//!   executable mapping of a role process needs no mark: it is judged when
//!   it is made, on its file ([`code_verdict`]). A main image without the
//!   mark, or a mapping that is not trusted code, takes the role away,
//!   signed (`started_for_the_role` and the exemption ask for it).
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

/// Lot 2.2 (the review of #644, decision D10): why the code an executable
/// mapping brings into a role process is not trusted — 0 when it is. A
/// role process's MAIN image must carry [`MARK_ROLE`] (the agent's or the
/// watchdog's binary, as the install or the upgrade put it in place, inside
/// a window); every other executable mapping (`mmap` with `PROT_EXEC`, an
/// `mprotect` that adds it) is judged when it is made, on its file, by the
/// window's exec rule's test (the design's section 4): a regular file,
/// owned by root of the initial user namespace, writable by neither its
/// group nor others, with a name (not a memfd, an `O_TMPFILE` or a file
/// already deleted), on a local filesystem (not FUSE, not a network one) of
/// the initial user namespace, through a mount that is not idmapped. It is
/// never judged again later: a library deleted after it was mapped (the
/// old C library after an upgrade without a reboot) was trusted when it
/// was mapped and stays so.
pub const CODE_TRUSTED: u32 = 0;
/// No file: anonymous memory (or an `mprotect` of an anonymous mapping).
pub const CODE_ANONYMOUS: u32 = 1;
/// The main image has no [`MARK_ROLE`].
pub const CODE_MAIN_UNMARKED: u32 = 2;
/// Not a regular file.
pub const CODE_NOT_REGULAR: u32 = 3;
/// Not owned by root of the initial user namespace.
pub const CODE_NOT_ROOT: u32 = 4;
/// Writable by its group or by others.
pub const CODE_WRITABLE: u32 = 5;
/// No name: a memfd, an `O_TMPFILE`, a file deleted before its mapping.
pub const CODE_NO_NAME: u32 = 6;
/// On FUSE (`virtiofs` aside: the hypervisor's share) or a network
/// filesystem.
pub const CODE_REMOTE_FS: u32 = 7;
/// On a superblock of another user namespace than the initial one.
pub const CODE_FOREIGN_SB: u32 = 8;
/// Through an idmapped mount.
pub const CODE_IDMAPPED: u32 = 9;

/// `S_IFMT`, `S_IFREG` (include/uapi/linux/stat.h).
pub const S_IFMT: u32 = 0o170_000;
pub const S_IFREG: u32 = 0o100_000;

/// The superblock magics of FUSE and of the network filesystems
/// (include/uapi/linux/magic.h, fs/smb, fs/ceph, fs/afs, fs/9p,
/// fs/orangefs): FUSE, NFS, SMB, CIFS, SMB2, Ceph, 9P, AFS (both), Coda,
/// NCP, OrangeFS.
pub const REMOTE_FS_MAGICS: [u64; 12] = [
    0x6573_5546,
    0x6969,
    0x517b,
    0xff53_4d42,
    0xfe53_4d42,
    0x00c3_6400,
    0x0102_1997,
    0x6b41_4653,
    0x5346_414f,
    0x7375_7245,
    0x564c,
    0x2003_0528,
];
/// `FUSE_SUPER_MAGIC`: `virtiofs` shares it.
pub const FUSE_SUPER_MAGIC: u64 = 0x6573_5546;

/// What the hook read of a mapping's file ([`code_verdict`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodeFacts {
    /// `i_mode`.
    pub mode: u32,
    /// `i_uid` (a kernel uid: 0 is root of the initial user namespace).
    pub uid: u32,
    /// `i_nlink`; `None` where the kernel's field is not known.
    pub nlink: Option<u32>,
    /// The superblock's `s_magic`.
    pub magic: u64,
    /// The superblock's type is `virtiofs`.
    pub virtiofs: bool,
    /// The superblock's user namespace is not the initial one.
    pub foreign_sb: bool,
    /// The mount the file was opened through is idmapped.
    pub idmapped: bool,
}

/// [`CodeFacts`] judged: [`CODE_TRUSTED`], or the first reason the code is
/// not trusted. Pure, so that the hook's decision is tested here once.
#[inline(always)]
pub const fn code_verdict(f: &CodeFacts) -> u32 {
    if f.mode & S_IFMT != S_IFREG {
        return CODE_NOT_REGULAR;
    }
    if f.uid != 0 {
        return CODE_NOT_ROOT;
    }
    if f.mode & 0o022 != 0 {
        return CODE_WRITABLE;
    }
    if matches!(f.nlink, Some(0)) {
        return CODE_NO_NAME;
    }
    if is_remote_magic(f.magic) && !(f.magic == FUSE_SUPER_MAGIC && f.virtiofs) {
        return CODE_REMOTE_FS;
    }
    if f.foreign_sb {
        return CODE_FOREIGN_SB;
    }
    if f.idmapped {
        return CODE_IDMAPPED;
    }
    CODE_TRUSTED
}

/// `magic` is FUSE's or a network filesystem's ([`REMOTE_FS_MAGICS`]).
#[inline(always)]
pub const fn is_remote_magic(magic: u64) -> bool {
    let mut i = 0;
    while i < REMOTE_FS_MAGICS.len() {
        if REMOTE_FS_MAGICS[i] == magic {
            return true;
        }
        i += 1;
    }
    false
}

/// The verdict on one executable mapping of a role process: its main
/// image's marks (`main_marks`), and the mapped file's — its marks
/// (`file_marks`) and what was read of it (`facts`; `None`: no file, or
/// one that could not be read). The main image must carry [`MARK_ROLE`];
/// a mapped file that carries it is the main image or the other role's
/// binary; any other is judged by [`code_verdict`].
#[inline(always)]
pub const fn role_mapping_verdict(
    main_marks: Option<u32>,
    file_marks: Option<u32>,
    facts: Option<CodeFacts>,
) -> u32 {
    if unmarked_for_role(main_marks) {
        return CODE_MAIN_UNMARKED;
    }
    if !unmarked_for_role(file_marks) {
        return CODE_TRUSTED;
    }
    match facts {
        Some(f) => code_verdict(&f),
        None => CODE_ANONYMOUS,
    }
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

    fn lib() -> CodeFacts {
        CodeFacts {
            mode: S_IFREG | 0o644,
            uid: 0,
            nlink: Some(1),
            magic: 0xef53,
            virtiofs: false,
            foreign_sb: false,
            idmapped: false,
        }
    }

    /// The review of #644 (D10, F1): the C library and the loader replaced
    /// under a running role (dpkg renames the new file over the old one):
    /// the restarted role maps the NEW files, unmarked, root's, on the
    /// local filesystem — trusted code, the role kept. The old files, now
    /// deleted, are never judged again (the hooks judge a mapping when it is
    /// made); a file already deleted when it is mapped has no name.
    #[test]
    fn a_library_upgraded_under_a_running_role_keeps_the_role_at_its_restart() {
        let main = Some(MARK_ROLE);
        let new_libc = lib();
        let new_ldso = CodeFacts {
            mode: S_IFREG | 0o755,
            ..lib()
        };
        assert_eq!(
            role_mapping_verdict(main, None, Some(new_libc)),
            CODE_TRUSTED
        );
        assert_eq!(
            role_mapping_verdict(main, None, Some(new_ldso)),
            CODE_TRUSTED
        );
        // the main image, or the other role's binary
        assert_eq!(role_mapping_verdict(main, main, None), CODE_TRUSTED);
        let deleted_when_mapped = CodeFacts {
            nlink: Some(0),
            ..lib()
        };
        assert_eq!(
            role_mapping_verdict(main, None, Some(deleted_when_mapped)),
            CODE_NO_NAME
        );
        // a kernel whose i_nlink is unknown: not refused for it
        let unknown_nlink = CodeFacts {
            nlink: None,
            ..lib()
        };
        assert_eq!(code_verdict(&unknown_nlink), CODE_TRUSTED);
    }

    /// The review of #644 (D10, F2): an NSS module (and its dependencies)
    /// opened with `dlopen` after the marks were armed — no mark, root's,
    /// local — keeps the running role; on a VM's `virtiofs` share (the
    /// hypervisor's, FUSE's magic) too.
    #[test]
    fn an_nss_module_opened_after_the_start_keeps_the_role() {
        let main = Some(MARK_ROLE);
        assert_eq!(role_mapping_verdict(main, None, Some(lib())), CODE_TRUSTED);
        assert_eq!(
            role_mapping_verdict(main, Some(0), Some(lib())),
            CODE_TRUSTED
        );
        assert_eq!(
            role_mapping_verdict(main, Some(1 << 8), Some(lib())),
            CODE_TRUSTED,
            "an S12 mark alone changes nothing"
        );
        let virtiofs = CodeFacts {
            magic: FUSE_SUPER_MAGIC,
            virtiofs: true,
            ..lib()
        };
        assert_eq!(
            role_mapping_verdict(main, None, Some(virtiofs)),
            CODE_TRUSTED
        );
    }

    /// D10: an untrusted mapping takes the role away (the hook records the
    /// loss and signs it on any verdict but trusted: the xtask ratchet
    /// `an_unmarked_executable_mapping_takes_the_role_away`) — each reason,
    /// one at a time.
    #[test]
    fn an_untrusted_mapping_takes_the_role_away_by_its_first_reason() {
        let cases = [
            (
                CodeFacts {
                    mode: 0o020_644,
                    ..lib()
                },
                CODE_NOT_REGULAR,
            ),
            (
                CodeFacts {
                    mode: 0o644,
                    ..lib()
                },
                CODE_NOT_REGULAR,
            ),
            (CodeFacts { uid: 1000, ..lib() }, CODE_NOT_ROOT),
            (
                CodeFacts {
                    mode: S_IFREG | 0o664,
                    ..lib()
                },
                CODE_WRITABLE,
            ),
            (
                CodeFacts {
                    mode: S_IFREG | 0o646,
                    ..lib()
                },
                CODE_WRITABLE,
            ),
            (
                CodeFacts {
                    mode: S_IFREG | 0o777,
                    ..lib()
                },
                CODE_WRITABLE,
            ),
            (
                CodeFacts {
                    nlink: Some(0),
                    ..lib()
                },
                CODE_NO_NAME,
            ),
            (
                CodeFacts {
                    magic: FUSE_SUPER_MAGIC,
                    ..lib()
                },
                CODE_REMOTE_FS,
            ),
            (
                CodeFacts {
                    magic: 0x6969,
                    ..lib()
                },
                CODE_REMOTE_FS,
            ),
            (
                CodeFacts {
                    magic: 0xfe53_4d42,
                    ..lib()
                },
                CODE_REMOTE_FS,
            ),
            (
                CodeFacts {
                    magic: 0x2003_0528,
                    ..lib()
                },
                CODE_REMOTE_FS,
            ),
            (
                CodeFacts {
                    magic: 0x6969,
                    virtiofs: true,
                    ..lib()
                },
                CODE_REMOTE_FS,
            ),
            (
                CodeFacts {
                    foreign_sb: true,
                    ..lib()
                },
                CODE_FOREIGN_SB,
            ),
            (
                CodeFacts {
                    idmapped: true,
                    ..lib()
                },
                CODE_IDMAPPED,
            ),
            // a memfd: root's, 0777, no name — its first reason
            (
                CodeFacts {
                    mode: S_IFREG | 0o777,
                    nlink: Some(0),
                    magic: 0x0102_1994,
                    ..lib()
                },
                CODE_WRITABLE,
            ),
        ];
        for (facts, want) in cases {
            assert_eq!(code_verdict(&facts), want, "{facts:?}");
            assert_eq!(
                role_mapping_verdict(Some(MARK_ROLE), None, Some(facts)),
                want,
                "{facts:?}"
            );
        }
        for m in REMOTE_FS_MAGICS {
            assert!(is_remote_magic(m));
        }
        assert!(!is_remote_magic(0xef53));
        assert!(!is_remote_magic(0x0102_1994), "tmpfs is local");
    }

    /// D10: a role process whose main image has no role mark keeps nothing,
    /// whatever it maps; anonymous memory is no trusted code; a mark other
    /// than the role's is no role image.
    #[test]
    fn the_main_image_must_carry_the_role_mark() {
        for main in [None, Some(0), Some(1 << 8)] {
            assert_eq!(
                role_mapping_verdict(main, Some(MARK_ROLE), Some(lib())),
                CODE_MAIN_UNMARKED
            );
        }
        assert_eq!(
            role_mapping_verdict(Some(MARK_ROLE), None, None),
            CODE_ANONYMOUS
        );
        assert_eq!(
            role_mapping_verdict(Some(MARK_ROLE), Some(1 << 8), None),
            CODE_ANONYMOUS
        );
        let codes = [
            CODE_TRUSTED,
            CODE_ANONYMOUS,
            CODE_MAIN_UNMARKED,
            CODE_NOT_REGULAR,
            CODE_NOT_ROOT,
            CODE_WRITABLE,
            CODE_NO_NAME,
            CODE_REMOTE_FS,
            CODE_FOREIGN_SB,
            CODE_IDMAPPED,
        ];
        for (i, a) in codes.iter().enumerate() {
            assert_eq!(*a, i as u32);
        }
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
