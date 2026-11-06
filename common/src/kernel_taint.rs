//! Lot 280b: the kernel's taint flags (`/proc/sys/kernel/tainted`), the
//! ones that say foreign code entered the kernel, and how much a new one
//! weighs.
//!
//! A flag is set by the kernel once and never cleared while it runs: a new
//! one is an event of this boot. A module that is not the distribution's,
//! one loaded by force or unsigned, a forced unload, a livepatch — each
//! changes the code the agent's hooks run beside (a livepatch replaces
//! kernel functions, the ones a hook is attached to included). The agent's
//! kernel-state round signs a new one of [`CODE_ENTRY`] as a detection,
//! Critical when it is one of [`CRITICAL`]; every flag is in the signed
//! capability manifest. The numbers are `include/linux/panic.h`'s
//! (`TAINT_*`), the letters `kernel/panic.c`'s `taint_flags`.

/// `TAINT_PROPRIETARY_MODULE` (`P`).
pub const TAINT_PROPRIETARY_MODULE: u64 = 1 << 0;
/// `TAINT_FORCED_MODULE` (`F`): `insmod -f`, a module whose version
/// magic was not checked.
pub const TAINT_FORCED_MODULE: u64 = 1 << 1;
/// `TAINT_FORCED_RMMOD` (`R`): `rmmod -f`, a module removed while in use.
pub const TAINT_FORCED_RMMOD: u64 = 1 << 3;
/// `TAINT_CRAP` (`C`): a staging driver.
pub const TAINT_CRAP: u64 = 1 << 10;
/// `TAINT_OOT_MODULE` (`O`): an out-of-tree module.
pub const TAINT_OOT_MODULE: u64 = 1 << 12;
/// `TAINT_UNSIGNED_MODULE` (`E`): a module without a valid signature
/// (`module.sig_enforce=0`).
pub const TAINT_UNSIGNED_MODULE: u64 = 1 << 13;
/// `TAINT_LIVEPATCH` (`K`).
pub const TAINT_LIVEPATCH: u64 = 1 << 15;
/// `TAINT_AUX` (`X`): a distribution's own flag (SUSE: an unsupported
/// module).
pub const TAINT_AUX: u64 = 1 << 16;
/// `TAINT_TEST` (`N`): a test module (kunit).
pub const TAINT_TEST: u64 = 1 << 18;

/// The flags that say foreign code entered the kernel (or was forced out
/// of it): a new one is a detection.
pub const CODE_ENTRY: u64 = TAINT_PROPRIETARY_MODULE
    | TAINT_FORCED_MODULE
    | TAINT_FORCED_RMMOD
    | TAINT_CRAP
    | TAINT_OOT_MODULE
    | TAINT_UNSIGNED_MODULE
    | TAINT_LIVEPATCH
    | TAINT_AUX
    | TAINT_TEST;

/// The flags a detection is Critical for: a module the kernel could not
/// vouch for (unsigned), or one forced in or out.
pub const CRITICAL: u64 = TAINT_FORCED_MODULE | TAINT_FORCED_RMMOD | TAINT_UNSIGNED_MODULE;

/// Each flag's bit and letter, in the kernel's order.
pub const LETTERS: [(u32, u8); 20] = [
    (0, b'P'),
    (1, b'F'),
    (2, b'S'),
    (3, b'R'),
    (4, b'M'),
    (5, b'B'),
    (6, b'U'),
    (7, b'D'),
    (8, b'A'),
    (9, b'W'),
    (10, b'C'),
    (11, b'I'),
    (12, b'O'),
    (13, b'E'),
    (14, b'L'),
    (15, b'K'),
    (16, b'X'),
    (17, b'T'),
    (18, b'N'),
    (19, b'J'),
];

/// The flags of [`CODE_ENTRY`] set in `now` and not in `before`.
#[inline(always)]
pub const fn new_code_entry(before: u64, now: u64) -> u64 {
    now & !before & CODE_ENTRY
}

/// Whether a detection of the flags `new` is Critical (else High).
#[inline(always)]
pub const fn is_critical(new: u64) -> bool {
    new & CRITICAL != 0
}

/// The letters of `mask`'s flags in the kernel's order; a bit the table
/// does not name as `#<bit>` (a newer kernel's flag).
#[cfg(feature = "std")]
pub fn letters(mask: u64) -> alloc::string::String {
    use alloc::string::String;
    let mut out = String::new();
    for bit in 0..64u32 {
        if mask & (1u64 << bit) == 0 {
            continue;
        }
        match LETTERS.iter().find(|(b, _)| *b == bit) {
            Some((_, l)) => out.push(*l as char),
            None => {
                if !out.is_empty() {
                    out.push(' ');
                }
                out.push_str(&alloc::format!("#{bit}"));
            }
        }
    }
    out
}

/// What a flag of [`CODE_ENTRY`] means, for the detection's reasoning.
#[cfg(feature = "std")]
pub fn meaning(mask: u64) -> alloc::vec::Vec<&'static str> {
    const NAMES: [(u64, &str); 9] = [
        (TAINT_PROPRIETARY_MODULE, "P: a proprietary module"),
        (TAINT_FORCED_MODULE, "F: a module loaded by force"),
        (TAINT_FORCED_RMMOD, "R: a module removed by force"),
        (TAINT_CRAP, "C: a staging driver"),
        (TAINT_OOT_MODULE, "O: an out-of-tree module"),
        (TAINT_UNSIGNED_MODULE, "E: an unsigned module"),
        (TAINT_LIVEPATCH, "K: a livepatch"),
        (TAINT_AUX, "X: a distribution's auxiliary taint"),
        (TAINT_TEST, "N: a test module"),
    ];
    NAMES
        .iter()
        .filter(|(b, _)| mask & b != 0)
        .map(|(_, n)| *n)
        .collect()
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    /// The bits and letters are the kernel's (`kernel/panic.c`).
    #[test]
    fn the_flags_are_the_kernels() {
        assert_eq!(letters(0), "");
        assert_eq!(letters(TAINT_OOT_MODULE | TAINT_UNSIGNED_MODULE), "OE");
        assert_eq!(letters(TAINT_LIVEPATCH), "K");
        assert_eq!(letters(1 << 9), "W");
        assert_eq!(
            letters(TAINT_PROPRIETARY_MODULE | TAINT_FORCED_MODULE),
            "PF"
        );
        assert_eq!(letters(TAINT_FORCED_RMMOD), "R");
        assert_eq!(letters(1 << 19), "J");
        assert_eq!(letters(1 << 20), "#20");
        assert_eq!(letters(TAINT_LIVEPATCH | (1 << 33)), "K #33");
        for (i, (bit, _)) in LETTERS.iter().enumerate() {
            assert_eq!(*bit, i as u32);
        }
        assert_eq!(TAINT_UNSIGNED_MODULE, 8192);
        assert_eq!(TAINT_LIVEPATCH, 32768);
        assert_eq!(TAINT_OOT_MODULE, 4096);
    }

    /// Only a flag of code entering the kernel is new code: a warning, an
    /// oops, a lockup, a machine check, a user's taint are not; a flag
    /// already set is not new.
    #[test]
    fn only_a_new_code_entry_flag_counts() {
        assert_eq!(
            new_code_entry(0, TAINT_UNSIGNED_MODULE),
            TAINT_UNSIGNED_MODULE
        );
        assert_eq!(
            new_code_entry(TAINT_UNSIGNED_MODULE, TAINT_UNSIGNED_MODULE),
            0
        );
        assert_eq!(
            new_code_entry(TAINT_OOT_MODULE, TAINT_OOT_MODULE | TAINT_LIVEPATCH),
            TAINT_LIVEPATCH
        );
        for bit in [2, 4, 5, 6, 7, 8, 9, 11, 14, 17, 19] {
            assert_eq!(new_code_entry(0, 1 << bit), 0, "bit {bit}");
        }
        for bit in [0, 1, 3, 10, 12, 13, 15, 16, 18] {
            assert_eq!(new_code_entry(0, 1 << bit), 1 << bit, "bit {bit}");
        }
        assert_eq!(meaning(CODE_ENTRY).len(), 9);
        assert_eq!(meaning(TAINT_LIVEPATCH), vec!["K: a livepatch"]);
    }

    /// Critical for an unsigned module and for anything forced; High for
    /// the rest (an out-of-tree or proprietary module, a livepatch).
    #[test]
    fn unsigned_and_forced_are_critical() {
        for f in [
            TAINT_UNSIGNED_MODULE,
            TAINT_FORCED_MODULE,
            TAINT_FORCED_RMMOD,
        ] {
            assert!(is_critical(f));
            assert!(is_critical(f | TAINT_OOT_MODULE));
        }
        for f in [
            TAINT_PROPRIETARY_MODULE,
            TAINT_CRAP,
            TAINT_OOT_MODULE,
            TAINT_LIVEPATCH,
            TAINT_AUX,
            TAINT_TEST,
        ] {
            assert!(!is_critical(f));
        }
    }
}
