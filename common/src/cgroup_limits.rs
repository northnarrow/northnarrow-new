//! Lot 273b: the resource files of the protected units' cgroups and of
//! their ancestor slices — which ones are refused, and the one write PID 1
//! may make.
//!
//! A low `memory.max` is an OOM kill inside the write itself; `cpu.max`,
//! `cpu.idle`, `cpu.weight` and `pids.max` starve the agent as a freeze
//! does (`pids.max` also stops the actuators' execs); `cgroup.max.*` on a
//! slice keeps the next start from making its cgroup; `memory.oom.group`
//! on a slice turns one OOM into the kill of every unit in it; `io.max`
//! throttles the agent's writes to nothing. The deny hooks refuse a write
//! of these files in a protected cgroup from anyone but the agent's family
//! and PID 1 outside a trusted-installer window. systemd writes them as
//! PID 1 whenever it realises a unit (a start, a `set-property`, a
//! reload): PID 1's write is let through when it puts back the value the
//! file held at the registration (what the unit started with), or the
//! kernel's default for a file that appeared later; any other value — a
//! `set-property` lowering or raising a limit — is a change of the unit,
//! made inside a window.
//!
//! The eBPF programs and the agent share this module: the names, the
//! values and their comparison are tested once, here.

use crate::wire::{CGROUP2_SUPER_MAGIC, CGROUP_SUPER_MAGIC, PROC_SUPER_MAGIC};

/// Not a protected resource file.
pub const LIMIT_NONE: u8 = 0;
/// `max` or a number of bytes / tasks / cgroups, higher is better
/// (`memory.max`, `memory.high`, `pids.max`, `cgroup.max.descendants`,
/// `cgroup.max.depth`).
pub const LIMIT_UNSIGNED_MAX: u8 = 1;
/// A number, higher is better, no `max` (`cpu.weight`, 1 to 10000).
pub const LIMIT_WEIGHT: u8 = 2;
/// `$QUOTA $PERIOD` or `max [$PERIOD]` (`cpu.max`): the share of a CPU,
/// higher is better.
pub const LIMIT_CPU_MAX: u8 = 3;
/// `0` or `1`, `0` is better (`cpu.idle`, `memory.oom.group`).
pub const LIMIT_FLAG: u8 = 4;
/// A nice value, -20 to 19, lower is better (`cpu.weight.nice`).
pub const LIMIT_NICE: u8 = 5;
/// `$MAJ:$MIN key=value ...` (`io.max`): only `max` values (a limit
/// removed) are no worse.
pub const LIMIT_IO_MAX: u8 = 6;
/// Lot 273c (the review of #490): a CPU or memory-node list (`cpuset.cpus`,
/// `cpuset.mems`): the agent pinned to one CPU a real-time hog owns
/// starves. Empty by default (the parent's).
pub const LIMIT_CPU_LIST: u8 = 7;
/// Lot 273c: `cpuset.cpus.partition` (`member` by default).
pub const LIMIT_PARTITION: u8 = 8;
/// Lot 273c: `memory.reclaim`, write-only: every write forces a reclaim
/// (a thrash of the agent's memory, repeated). Never PID 1's either: no
/// value to put back.
pub const LIMIT_RECLAIM: u8 = 9;
/// Lot 273c: `io.weight` / `io.bfq.weight` (`default 100`, then per
/// device): a weight of 1 starves the agent's I/O under contention.
pub const LIMIT_IO_WEIGHT: u8 = 10;
/// Lot 273d (the review of #492): `io.prio.class` (5.14 and later,
/// `no-change` by default): `idle` starves the agent's writes — its audit
/// log, its chains — under contention.
pub const LIMIT_IO_PRIO_CLASS: u8 = 11;

/// The protected resource files and their kinds.
pub const LIMIT_FILES: [(&str, u8); 18] = [
    ("memory.max", LIMIT_UNSIGNED_MAX),
    ("memory.high", LIMIT_UNSIGNED_MAX),
    ("pids.max", LIMIT_UNSIGNED_MAX),
    ("cgroup.max.descendants", LIMIT_UNSIGNED_MAX),
    ("cgroup.max.depth", LIMIT_UNSIGNED_MAX),
    ("cpu.weight", LIMIT_WEIGHT),
    ("cpu.max", LIMIT_CPU_MAX),
    ("cpu.idle", LIMIT_FLAG),
    ("memory.oom.group", LIMIT_FLAG),
    ("cpu.weight.nice", LIMIT_NICE),
    ("io.max", LIMIT_IO_MAX),
    // Lot 273c (the review of #490)
    ("cpuset.cpus", LIMIT_CPU_LIST),
    ("cpuset.mems", LIMIT_CPU_LIST),
    ("cpuset.cpus.partition", LIMIT_PARTITION),
    ("memory.reclaim", LIMIT_RECLAIM),
    ("io.weight", LIMIT_IO_WEIGHT),
    ("io.bfq.weight", LIMIT_IO_WEIGHT),
    // Lot 273d (the review of #492)
    ("io.prio.class", LIMIT_IO_PRIO_CLASS),
];

/// The longest name the eBPF programs read (`cgroup.max.descendants`, 22
/// bytes, fits): three little-endian words.
pub const LIMIT_NAME_MAX: usize = 24;

/// `name` as the eBPF programs compare it: its first [`LIMIT_NAME_MAX`]
/// bytes in three little-endian words, zero past its end.
pub const fn name_words(name: &[u8]) -> [u64; 3] {
    let mut w = [0u64; 3];
    let mut i = 0;
    while i < name.len() && i < LIMIT_NAME_MAX {
        w[i / 8] |= (name[i] as u64) << ((i % 8) * 8);
        i += 1;
    }
    w
}

/// The mask of the bytes of word `word` that lie inside a name of `len`
/// bytes (the eBPF programs read whole words and clear what follows the
/// name).
pub const fn word_mask(len: usize, word: usize) -> u64 {
    let start = word * 8;
    if len <= start {
        0
    } else if len - start >= 8 {
        u64::MAX
    } else {
        (1u64 << ((len - start) * 8)) - 1
    }
}

const fn limit_words() -> [(usize, [u64; 3], u8); LIMIT_FILES.len()] {
    let mut out = [(0usize, [0u64; 3], LIMIT_NONE); LIMIT_FILES.len()];
    let mut i = 0;
    while i < LIMIT_FILES.len() {
        let (name, kind) = LIMIT_FILES[i];
        out[i] = (name.len(), name_words(name.as_bytes()), kind);
        i += 1;
    }
    out
}

/// [`LIMIT_FILES`] as the eBPF programs compare names.
pub const LIMIT_WORDS: [(usize, [u64; 3], u8); LIMIT_FILES.len()] = limit_words();

/// The kind of the file named by `len` bytes packed in `w`
/// ([`name_words`]), or [`LIMIT_NONE`].
#[inline(always)]
pub fn limit_kind(len: usize, w: [u64; 3]) -> u8 {
    let mut i = 0;
    while i < LIMIT_WORDS.len() {
        let (l, words, kind) = LIMIT_WORDS[i];
        if l == len && words[0] == w[0] && words[1] == w[1] && words[2] == w[2] {
            return kind;
        }
        i += 1;
    }
    LIMIT_NONE
}

/// [`limit_kind`] of a name (userland and tests).
pub fn limit_kind_of(name: &str) -> u8 {
    if name.len() > LIMIT_NAME_MAX {
        return LIMIT_NONE;
    }
    limit_kind(name.len(), name_words(name.as_bytes()))
}

/// The bytes of a resource file's value the agent keeps (its text, the
/// trailing newline cut) and the eBPF programs compare: at most 31, the
/// rest of the 32 zero.
pub const LIMIT_TEXT_MAX: usize = 31;

/// A resource file's value as `LIMIT_VALUES` stores it and a write is
/// compared: its text in four little-endian words, zero past its end.
pub type LimitValue = [u64; 4];

/// `text` as a [`LimitValue`]: the bytes of a write as the eBPF program
/// reads them (zero past the count), or a file's text with its trailing
/// blanks cut. `None` past [`LIMIT_TEXT_MAX`] bytes.
pub const fn limit_value(text: &[u8]) -> Option<LimitValue> {
    let mut len = text.len();
    while len > 0 && is_blank(text[len - 1]) {
        len -= 1;
    }
    if len > LIMIT_TEXT_MAX {
        return None;
    }
    let mut v = [0u64; 4];
    let mut i = 0;
    while i < len {
        v[i / 8] |= (text[i] as u64) << ((i % 8) * 8);
        i += 1;
    }
    Some(v)
}

/// The value a file of `kind` starts with — what PID 1 may write to one
/// whose value was not registered (it appeared after the registration: a
/// controller enabled later), and what systemd writes for a unit that
/// sets nothing there: `max` (`max 100000` for `cpu.max`, the default
/// period), `cpu.weight` 100, `0` for the flags and the nice value.
/// `io.max` has none: an empty file, and no write that keeps it so.
pub const fn default_value(kind: u8) -> Option<LimitValue> {
    match kind {
        LIMIT_UNSIGNED_MAX => limit_value(b"max"),
        LIMIT_CPU_MAX => limit_value(b"max 100000"),
        LIMIT_WEIGHT => limit_value(b"100"),
        LIMIT_FLAG | LIMIT_NICE => limit_value(b"0"),
        // Lot 273c
        LIMIT_CPU_LIST => limit_value(b""),
        LIMIT_PARTITION => limit_value(b"member"),
        LIMIT_IO_WEIGHT => limit_value(b"default 100"),
        LIMIT_IO_PRIO_CLASS => limit_value(b"no-change"),
        _ => None,
    }
}

/// `written` (the bytes of a write of `count` bytes, zero past them) with
/// one trailing newline cleared: systemd writes a cgroup attribute with a
/// newline appended (`write_string_file()` without
/// `WRITE_STRING_FILE_AVOID_NEWLINE`: "11811160064\n", "0\n"), while a
/// registered value is the file's text with its newline cut. No loop and
/// no variable index (the eBPF verifier): the word holding the last byte
/// is picked by constant branches.
#[inline(always)]
pub const fn strip_newline(written: LimitValue, count: usize) -> LimitValue {
    let mut v = written;
    if count == 0 || count > 32 {
        return v;
    }
    let k = count - 1;
    let shift = (k % 8) * 8;
    let mask = 0xffu64 << shift;
    let nl = (b'\n' as u64) << shift;
    let w = k / 8;
    if w == 0 {
        if v[0] & mask == nl {
            v[0] &= !mask;
        }
    } else if w == 1 {
        if v[1] & mask == nl {
            v[1] &= !mask;
        }
    } else if w == 2 {
        if v[2] & mask == nl {
            v[2] &= !mask;
        }
    } else if v[3] & mask == nl {
        v[3] &= !mask;
    }
    v
}

/// Whether a write of `written` (the bytes read from it, zero past its
/// count, its trailing newline cleared: [`strip_newline`]) puts back
/// `value`: the same bytes. Four word compares, no loop:
/// the eBPF verifier walks it in a handful of instructions.
#[inline(always)]
pub const fn same_value(written: &LimitValue, value: &LimitValue) -> bool {
    (written[0] ^ value[0])
        | (written[1] ^ value[1])
        | (written[2] ^ value[2])
        | (written[3] ^ value[3])
        == 0
}

/// Whether PID 1's write of a protected resource file goes through
/// (systemd realising a unit, or a `set-property`'s copy): only when its
/// bytes could be read (`written`) and put back the value expected there
/// (`expected`: the registered one, else [`default_value`]). Any other
/// value, a file without an expected value, a write whose bytes cannot be
/// read: refused. Pure, so that the host's tests judge what the eBPF
/// program decides (the review of #490, its P2).
#[inline(always)]
pub const fn init_write_lets_through(
    expected: Option<LimitValue>,
    written: Option<LimitValue>,
) -> bool {
    match (expected, written) {
        (Some(e), Some(w)) => same_value(&w, &e),
        _ => false,
    }
}

/// The pseudo-filesystems whose files the write deny judges.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SpecialFs {
    /// cgroup v2: a unit's resource files.
    Cgroup2,
    /// A cgroup v1 hierarchy.
    CgroupV1,
    /// procfs: `oom_score_adj`, `oom_adj`.
    Proc,
}

/// The filesystem of a superblock whose `s_magic` is `s_magic`, when the
/// write deny judges its files. `s_magic` is an `unsigned long`; the
/// magics are 32-bit, the upper half is ignored. Pure, so that the host's
/// tests see a wrong mask or magic (the review of #490, its P3: a mask of
/// 16 bits left every cgroup file unjudged).
#[inline(always)]
pub const fn special_fs(s_magic: u64) -> Option<SpecialFs> {
    match s_magic & 0xffff_ffff {
        CGROUP2_SUPER_MAGIC => Some(SpecialFs::Cgroup2),
        CGROUP_SUPER_MAGIC => Some(SpecialFs::CgroupV1),
        PROC_SUPER_MAGIC => Some(SpecialFs::Proc),
        _ => None,
    }
}

/// Lot 273d (the review of #492): the global sysctls whose value aborts or
/// starves the agent with the rest of the host — `vm.overcommit_memory=2`
/// with a low ratio (its next allocation fails), a `pid_max`, `threads-max`
/// or `max_map_count` cut below what it runs, real-time throttling off
/// (`sched_rt_runtime_us=-1`: a real-time hog owns the CPUs) — or blinds
/// it: `kernel.ftrace_enabled=0` (R1 of the external review of 04/11)
/// turns every call site ftrace manages back into a NOP on 6.0 to 7.2,
/// with no error, and the BPF trampolines on them with it (fentry/fexit,
/// the kprobes on ftrace and, by the kernel's code, the BPF-LSM programs:
/// every deny hook). Not a sysctl of these.
pub const SYSCTL_NONE: u8 = 0;
pub const SYSCTL_OVERCOMMIT_MEMORY: u8 = 1;
pub const SYSCTL_OVERCOMMIT_RATIO: u8 = 2;
pub const SYSCTL_OVERCOMMIT_KBYTES: u8 = 3;
pub const SYSCTL_MAX_MAP_COUNT: u8 = 4;
pub const SYSCTL_PID_MAX: u8 = 5;
pub const SYSCTL_THREADS_MAX: u8 = 6;
pub const SYSCTL_SCHED_RT_RUNTIME: u8 = 7;
pub const SYSCTL_FTRACE_ENABLED: u8 = 8;

/// The guarded sysctls by their `/proc/sys` file name (unique in procfs:
/// no `/proc/<pid>` file is named so), and their kinds.
pub const SYSCTL_FILES: [(&str, u8); 8] = [
    ("overcommit_memory", SYSCTL_OVERCOMMIT_MEMORY),
    ("overcommit_ratio", SYSCTL_OVERCOMMIT_RATIO),
    ("overcommit_kbytes", SYSCTL_OVERCOMMIT_KBYTES),
    ("max_map_count", SYSCTL_MAX_MAP_COUNT),
    ("pid_max", SYSCTL_PID_MAX),
    ("threads-max", SYSCTL_THREADS_MAX),
    ("sched_rt_runtime_us", SYSCTL_SCHED_RT_RUNTIME),
    ("ftrace_enabled", SYSCTL_FTRACE_ENABLED),
];

const fn sysctl_words() -> [(usize, [u64; 3], u8); SYSCTL_FILES.len()] {
    let mut out = [(0usize, [0u64; 3], SYSCTL_NONE); SYSCTL_FILES.len()];
    let mut i = 0;
    while i < SYSCTL_FILES.len() {
        let (name, kind) = SYSCTL_FILES[i];
        out[i] = (name.len(), name_words(name.as_bytes()), kind);
        i += 1;
    }
    out
}

/// [`SYSCTL_FILES`]' names as the eBPF programs compare them.
pub const SYSCTL_WORDS: [(usize, [u64; 3], u8); SYSCTL_FILES.len()] = sysctl_words();

/// The kind of the procfs file of `len` bytes and name words `w`.
#[inline(always)]
pub fn sysctl_kind(len: usize, w: [u64; 3]) -> u8 {
    let mut i = 0;
    while i < SYSCTL_WORDS.len() {
        let (l, n, kind) = SYSCTL_WORDS[i];
        if l == len && n[0] == w[0] && n[1] == w[1] && n[2] == w[2] {
            return kind;
        }
        i += 1;
    }
    SYSCTL_NONE
}

/// [`parse_i64`]'s state after a byte.
#[derive(Clone, Copy)]
struct Parsed {
    n: i64,
    digits: u32,
    neg: bool,
    /// a terminator seen: the bytes after it are not the value's
    end: bool,
    /// not an integer (or longer than 18 digits)
    bad: bool,
}

/// [`parse_i64`]'s step: byte `i` of `v`.
#[inline(always)]
const fn parse_step(p: Parsed, v: &LimitValue, i: usize) -> Parsed {
    if p.end || p.bad {
        return p;
    }
    let b = ((v[i / 8] >> ((i % 8) * 8)) & 0xff) as u8;
    if b == 0 || b == b'\n' || b == b' ' || b == b'\t' {
        return Parsed { end: true, ..p };
    }
    if i == 0 && b == b'-' {
        return Parsed { neg: true, ..p };
    }
    if b.is_ascii_digit() && p.digits < 18 {
        return Parsed {
            n: p.n * 10 + (b - b'0') as i64,
            digits: p.digits + 1,
            ..p
        };
    }
    Parsed { bad: true, ..p }
}

/// A written decimal integer (an optional `-`, digits, then the end or a
/// blank), `None` when it is not one; 24 bytes at most. Lot 273d's lab
/// (round 12): written as a loop, LLVM laid it out with a fall-through
/// back-edge that the 5.15 and 6.1 verifiers reject (`back-edge from insn
/// … to …`: `loop_ok` is false for a non-jump instruction's edge there),
/// and the write deny did not load on those kernels — so it is unrolled,
/// one step per byte, no loop at all.
#[inline(always)]
pub const fn parse_i64(v: &LimitValue) -> Option<i64> {
    macro_rules! steps {
        ($p:ident; $($i:literal)*) => { $( let $p = parse_step($p, v, $i); )* };
    }
    let p = Parsed {
        n: 0,
        digits: 0,
        neg: false,
        end: false,
        bad: false,
    };
    steps!(p; 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23);
    if p.bad || p.digits == 0 {
        return None;
    }
    Some(if p.neg { -p.n } else { p.n })
}

/// Whether a write of `written` (its bytes, `None`: unread) to the sysctl
/// of `kind` aborts or starves the agent: refused outside a window. An
/// unread or unparsable write is refused like PID 1's unread write.
#[inline(always)]
pub const fn sysctl_write_harmful(kind: u8, written: Option<LimitValue>) -> bool {
    let v = match written {
        Some(w) => match parse_i64(&w) {
            Some(v) => v,
            None => return true,
        },
        None => return true,
    };
    match kind {
        SYSCTL_OVERCOMMIT_MEMORY => v == 2,
        SYSCTL_OVERCOMMIT_RATIO => v < 50,
        // 0: the ratio decides; else a cap below 1 GiB
        SYSCTL_OVERCOMMIT_KBYTES => v != 0 && v < 1 << 20,
        SYSCTL_MAX_MAP_COUNT => v < 65530,
        SYSCTL_PID_MAX => v < 32768,
        SYSCTL_THREADS_MAX => v < 8192,
        // -1: no throttling; at or past 99 % of the default period, almost none
        SYSCTL_SCHED_RT_RUNTIME => v < 0 || v >= 990_000,
        // 0 stops ftrace (the kernel reads any other integer as on): the
        // value the round puts back. A write of it is refused whatever it
        // carries ([`sysctl_refuses_every_write`]).
        SYSCTL_FTRACE_ENABLED => v == 0,
        _ => false,
    }
}

/// R1 (the coordinator's decision of 04/11): the sysctls of which every
/// write is refused outside a window, whatever its value — `ftrace_enabled`:
/// no legitimate use of writing it is known (upstream deprecates it and
/// refuses it from 7.3; a 1 over a 1 changes nothing), and with no value
/// to judge there is no byte to read before the kernel copies it, so a
/// second thread of the writer has nothing to race (the other seven are
/// judged by value: lot 280 closes their race with `cgroup/sysctl`).
#[inline(always)]
pub const fn sysctl_refuses_every_write(kind: u8) -> bool {
    kind == SYSCTL_FTRACE_ENABLED
}

/// The write deny's verdict on a write of the guarded sysctl of `kind`:
/// the agent's family and a trusted-installer window (`caller_may`: the
/// identity every guarded write is let through by — the round's own
/// restore among them, never an exception by name) pass; outside them a
/// sysctl of [`sysctl_refuses_every_write`] is refused without reading
/// the write, the others by the value `written` returns (read only then).
#[inline(always)]
pub fn sysctl_write_refused(
    kind: u8,
    caller_may: bool,
    written: impl FnOnce() -> Option<LimitValue>,
) -> bool {
    if kind == SYSCTL_NONE || caller_may {
        return false;
    }
    if sysctl_refuses_every_write(kind) {
        return true;
    }
    sysctl_write_harmful(kind, written())
}

#[inline(always)]
const fn is_blank(b: u8) -> bool {
    matches!(b, b' ' | b'\n' | b'\t' | b'\r')
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The files and their kinds, pinned: a file dropped from the table
    /// is a file no write of is refused.
    #[test]
    fn the_protected_files_are_these() {
        for (name, kind) in [
            ("memory.max", LIMIT_UNSIGNED_MAX),
            ("memory.high", LIMIT_UNSIGNED_MAX),
            ("pids.max", LIMIT_UNSIGNED_MAX),
            ("cgroup.max.descendants", LIMIT_UNSIGNED_MAX),
            ("cgroup.max.depth", LIMIT_UNSIGNED_MAX),
            ("cpu.weight", LIMIT_WEIGHT),
            ("cpu.max", LIMIT_CPU_MAX),
            ("cpu.idle", LIMIT_FLAG),
            ("memory.oom.group", LIMIT_FLAG),
            ("cpu.weight.nice", LIMIT_NICE),
            ("io.max", LIMIT_IO_MAX),
            ("cpuset.cpus", LIMIT_CPU_LIST),
            ("cpuset.mems", LIMIT_CPU_LIST),
            ("cpuset.cpus.partition", LIMIT_PARTITION),
            ("memory.reclaim", LIMIT_RECLAIM),
            ("io.weight", LIMIT_IO_WEIGHT),
            ("io.bfq.weight", LIMIT_IO_WEIGHT),
            ("io.prio.class", LIMIT_IO_PRIO_CLASS),
        ] {
            assert_eq!(limit_kind_of(name), kind, "{name}");
        }
        assert_eq!(LIMIT_FILES.len(), 18);
        // Lot 273c: the defaults systemd writes for a unit that sets none,
        // and none for memory.reclaim (no value to put back)
        assert_eq!(default_value(LIMIT_CPU_LIST), limit_value(b""));
        assert_eq!(default_value(LIMIT_PARTITION), limit_value(b"member"));
        assert_eq!(
            default_value(LIMIT_IO_PRIO_CLASS),
            limit_value(b"no-change")
        );
        assert_eq!(default_value(LIMIT_IO_WEIGHT), limit_value(b"default 100"));
        assert_eq!(default_value(LIMIT_RECLAIM), None);
    }

    #[test]
    fn every_file_is_found_by_its_words_and_nothing_else() {
        for (name, kind) in LIMIT_FILES {
            assert!(name.len() <= LIMIT_NAME_MAX, "{name}");
            assert_eq!(limit_kind_of(name), kind, "{name}");
        }
        for not in [
            "memory.ma",
            "memory.maxx",
            "memory.min",
            "memory.low",
            "memory.current",
            "cpu.weigh",
            "cpu.max.burst",
            "pids.current",
            "cgroup.procs",
            "cgroup.kill",
            "cgroup.freeze",
            "",
            "io.weigh",
            "io.stat",
            "cpuset.cpus.effective",
            "cpuset.mems.effective",
            "memory.reclaimX",
            "cgroup.max.descendantsX",
            "cgroup.max.descendants.and.more.bytes",
        ] {
            assert_eq!(limit_kind_of(not), LIMIT_NONE, "{not}");
        }
        // the words of a name read past its end are cleared by the mask
        let w = name_words(b"cpu.max\0garbage!");
        let masked = [
            w[0] & word_mask(7, 0),
            w[1] & word_mask(7, 1),
            w[2] & word_mask(7, 2),
        ];
        assert_eq!(limit_kind(7, masked), LIMIT_CPU_MAX);
        assert_eq!(word_mask(0, 0), 0);
        assert_eq!(word_mask(8, 0), u64::MAX);
        assert_eq!(word_mask(9, 1), 0xff);
        assert_eq!(word_mask(22, 2), 0xffff_ffff_ffff);
        assert_eq!(word_mask(24, 2), u64::MAX);
    }

    /// A write puts the value back when its bytes are the value's: a
    /// change, a longer or shorter value, another number, a newline the
    /// registration cut (systemd writes none) are another value.
    #[test]
    fn a_write_puts_the_value_back_only_byte_for_byte() {
        let v = limit_value(b"11811160064\n").unwrap();
        assert!(same_value(&limit_value(b"11811160064").unwrap(), &v));
        for other in [
            &b"11811160063"[..],
            b"1181116006",
            b"118111600640",
            b"4294967296",
            b"max",
            b"",
        ] {
            assert!(!same_value(&limit_value(other).unwrap(), &v), "{other:?}");
        }
        // the bytes of a write as the program reads them: zero past the count
        let mut w = [0u64; 4];
        for (i, b) in b"11811160064\n".iter().enumerate() {
            w[i / 8] |= (*b as u64) << ((i % 8) * 8);
        }
        assert!(!same_value(&w, &v), "a newline is another value unstripped");
        // systemd's write, its newline cleared, is the value
        assert!(same_value(&strip_newline(w, 12), &v));
        assert_eq!(
            strip_newline(w, 11),
            w,
            "the count says where the newline is"
        );
        // at every word's boundary
        for len in [1usize, 7, 8, 9, 15, 16, 17, 24, 25, 30] {
            let text: Vec<u8> = (0..len).map(|i| b'a' + (i % 26) as u8).collect();
            let mut with = text.clone();
            with.push(b'\n');
            let mut wv = [0u64; 4];
            for (i, b) in with.iter().enumerate() {
                wv[i / 8] |= (*b as u64) << ((i % 8) * 8);
            }
            assert!(
                same_value(&strip_newline(wv, len + 1), &limit_value(&text).unwrap()),
                "len {len}"
            );
        }
        assert_eq!(
            strip_newline(limit_value(b"0").unwrap(), 1),
            limit_value(b"0").unwrap(),
            "no newline: unchanged"
        );
        assert_eq!(strip_newline([1, 2, 3, 4], 0), [1, 2, 3, 4]);
        let cpu = limit_value(b"10000 100000\n").unwrap();
        assert!(same_value(&limit_value(b"10000 100000").unwrap(), &cpu));
        assert!(!same_value(&limit_value(b"1000 1000000").unwrap(), &cpu));
        // every word is compared: a difference in the third, in the fourth
        let long = limit_value(b"1234567890123456789012345678901").unwrap();
        for at in [2usize, 9, 18, 27, 30] {
            let mut t = *b"1234567890123456789012345678901";
            t[at] = b'x';
            assert!(!same_value(&limit_value(&t).unwrap(), &long), "byte {at}");
        }
        assert_eq!(limit_value(&[b'1'; 31]).map(|_| ()), Some(()));
        assert_eq!(limit_value(&[b'1'; 32]), None);
        assert_eq!(
            limit_value(b"512 \n\t").unwrap(),
            limit_value(b"512").unwrap()
        );
    }

    #[test]
    fn the_defaults_are_the_kernels() {
        assert_eq!(default_value(LIMIT_UNSIGNED_MAX), limit_value(b"max"));
        assert_eq!(default_value(LIMIT_CPU_MAX), limit_value(b"max 100000"));
        assert_eq!(default_value(LIMIT_WEIGHT), limit_value(b"100"));
        assert_eq!(default_value(LIMIT_FLAG), limit_value(b"0"));
        assert_eq!(default_value(LIMIT_NICE), limit_value(b"0"));
        assert_eq!(default_value(LIMIT_IO_MAX), None);
        assert_eq!(default_value(LIMIT_NONE), None);
    }

    /// The review of #490, its P2: PID 1 writes only the expected value.
    #[test]
    fn init_writes_only_the_value_expected_there() {
        let max = limit_value(b"max");
        let four_k = limit_value(b"4096");
        assert!(init_write_lets_through(max, max));
        assert!(init_write_lets_through(
            limit_value(b"536870912"),
            Some(strip_newline(limit_value(b"536870912\n").unwrap(), 10))
        ));
        // another value, a value it could not read, a file without one
        assert!(!init_write_lets_through(max, four_k));
        assert!(!init_write_lets_through(limit_value(b"536870912"), four_k));
        assert!(!init_write_lets_through(max, None));
        assert!(!init_write_lets_through(None, four_k));
        assert!(!init_write_lets_through(
            default_value(LIMIT_IO_MAX),
            limit_value(b"")
        ));
    }

    /// The review of #490, its P3: the three magics, their 32 bits only.
    #[test]
    fn the_judged_filesystems_are_found_by_their_32_bit_magic() {
        assert_eq!(special_fs(0x6367_7270), Some(SpecialFs::Cgroup2));
        assert_eq!(special_fs(0x0027_e0eb), Some(SpecialFs::CgroupV1));
        assert_eq!(special_fs(0x9fa0), Some(SpecialFs::Proc));
        assert_eq!(special_fs(0xffff_ffff_6367_7270), Some(SpecialFs::Cgroup2));
        // a 16-bit match is not one (tmpfs, ext4, sysfs, a 16-bit cut)
        assert_eq!(special_fs(0x7270), None);
        assert_eq!(special_fs(0xe0eb), None);
        assert_eq!(special_fs(0x0100_9fa0), None);
        assert_eq!(special_fs(0x0102_1994), None);
        assert_eq!(special_fs(0xef53), None);
        assert_eq!(special_fs(0x6265_6572), None);
    }

    /// Lot 273d: the guarded sysctls, judged by the value written.
    #[test]
    fn a_sysctl_write_is_harmful_by_its_value() {
        let w = |t: &[u8]| Some(limit_value(t).unwrap());
        let k = |n: &str| sysctl_kind(n.len(), name_words(n.as_bytes()));
        assert_eq!(k("overcommit_memory"), SYSCTL_OVERCOMMIT_MEMORY);
        assert_eq!(k("sched_rt_runtime_us"), SYSCTL_SCHED_RT_RUNTIME);
        assert_eq!(k("threads-max"), SYSCTL_THREADS_MAX);
        assert_eq!(k("ftrace_enabled"), SYSCTL_FTRACE_ENABLED);
        assert_eq!(k("ftrace_enable"), SYSCTL_NONE);
        assert_eq!(k("stack_tracer_enabled"), SYSCTL_NONE);
        assert_eq!(k("oom_score_adj"), SYSCTL_NONE);
        assert_eq!(k("pid_max2"), SYSCTL_NONE);
        assert_eq!(parse_i64(&limit_value(b"-1").unwrap()), Some(-1));
        assert_eq!(parse_i64(&limit_value(b"65530").unwrap()), Some(65530));
        assert_eq!(parse_i64(&limit_value(b"").unwrap()), None);
        assert_eq!(parse_i64(&limit_value(b"1x").unwrap()), None);
        // the unrolled steps: 18 digits, 19, a minus inside, after the end
        assert_eq!(
            parse_i64(&limit_value(b"123456789012345678").unwrap()),
            Some(123_456_789_012_345_678)
        );
        assert_eq!(
            parse_i64(&limit_value(b"1234567890123456789").unwrap()),
            None
        );
        assert_eq!(parse_i64(&limit_value(b"1-2").unwrap()), None);
        assert_eq!(parse_i64(&limit_value(b"-").unwrap()), None);
        assert_eq!(parse_i64(&limit_value(b"42 x").unwrap()), Some(42));
        assert_eq!(
            parse_i64(&limit_value(b"-950000\n").unwrap()),
            Some(-950_000)
        );
        assert_eq!(
            parse_i64(&limit_value(b"000000000000000007").unwrap()),
            Some(7)
        );
        assert_eq!(
            parse_i64(&limit_value(b"000000000000000000000007").unwrap()),
            None
        );
        for (kind, bad, good) in [
            (SYSCTL_OVERCOMMIT_MEMORY, &b"2"[..], &b"0"[..]),
            (SYSCTL_OVERCOMMIT_MEMORY, b"2", b"1"),
            (SYSCTL_OVERCOMMIT_RATIO, b"0", b"50"),
            (SYSCTL_OVERCOMMIT_KBYTES, b"1024", b"0"),
            (SYSCTL_MAX_MAP_COUNT, b"100", b"262144"),
            (SYSCTL_PID_MAX, b"300", b"4194304"),
            (SYSCTL_THREADS_MAX, b"64", b"126602"),
            (SYSCTL_SCHED_RT_RUNTIME, b"-1", b"950000"),
            (SYSCTL_SCHED_RT_RUNTIME, b"1000000", b"500000"),
            // R1: 0 in any spelling the kernel reads as 0 is refused, any
            // other integer (the kernel's "on") let through
            (SYSCTL_FTRACE_ENABLED, b"0", b"1"),
            (SYSCTL_FTRACE_ENABLED, b"0\n", b"1\n"),
            (SYSCTL_FTRACE_ENABLED, b"00", b"-1"),
            (SYSCTL_FTRACE_ENABLED, b"-0", b"2"),
            (SYSCTL_FTRACE_ENABLED, b"0x0", b"10"),
            (SYSCTL_FTRACE_ENABLED, b" 0", b"1 0"),
        ] {
            assert!(sysctl_write_harmful(kind, w(bad)), "{kind} {bad:?}");
            assert!(!sysctl_write_harmful(kind, w(good)), "{kind} {good:?}");
        }
        // a write whose bytes could not be read is refused
        assert!(sysctl_write_harmful(SYSCTL_PID_MAX, None));
        assert!(sysctl_write_harmful(SYSCTL_FTRACE_ENABLED, None));
    }

    /// R1 (the coordinator's decision of 04/11): every write of
    /// `ftrace_enabled` outside a window is refused, 1 too, and its bytes
    /// are never read (nothing for a second thread to race); the agent's
    /// own restore and a window's write pass by the caller's identity, as
    /// every guarded sysctl's do; the other seven stay judged by value.
    #[test]
    fn ftrace_enabled_is_refused_whatever_it_carries() {
        let w = |t: &'static [u8]| move || Some(limit_value(t).unwrap());
        let unread = || -> Option<LimitValue> { panic!("ftrace_enabled's write was read") };
        assert!(sysctl_refuses_every_write(SYSCTL_FTRACE_ENABLED));
        assert!(sysctl_write_refused(SYSCTL_FTRACE_ENABLED, false, unread));
        assert!(sysctl_write_refused(SYSCTL_FTRACE_ENABLED, false, w(b"1")));
        // the round's restore (the agent's family) and a window
        assert!(!sysctl_write_refused(SYSCTL_FTRACE_ENABLED, true, unread));
        assert!(!sysctl_write_refused(SYSCTL_FTRACE_ENABLED, true, w(b"1")));
        // the round puts back only a 0
        assert!(sysctl_write_harmful(SYSCTL_FTRACE_ENABLED, w(b"0")()));
        assert!(!sysctl_write_harmful(SYSCTL_FTRACE_ENABLED, w(b"1")()));
        // the other seven by value, only outside the caller's identity
        for kind in [
            SYSCTL_OVERCOMMIT_MEMORY,
            SYSCTL_OVERCOMMIT_RATIO,
            SYSCTL_OVERCOMMIT_KBYTES,
            SYSCTL_MAX_MAP_COUNT,
            SYSCTL_PID_MAX,
            SYSCTL_THREADS_MAX,
            SYSCTL_SCHED_RT_RUNTIME,
        ] {
            assert!(!sysctl_refuses_every_write(kind), "{kind}");
            assert!(!sysctl_write_refused(kind, true, unread), "{kind}");
        }
        assert!(sysctl_write_refused(SYSCTL_MAX_MAP_COUNT, false, w(b"100")));
        assert!(!sysctl_write_refused(
            SYSCTL_MAX_MAP_COUNT,
            false,
            w(b"262144")
        ));
        assert!(!sysctl_write_refused(SYSCTL_NONE, false, unread));
    }

    /// The guarded sysctls, pinned: a file dropped from the table is a
    /// file no write of is refused (R1: `ftrace_enabled` among them).
    #[test]
    fn the_guarded_sysctls_are_these() {
        assert_eq!(
            SYSCTL_FILES.as_slice(),
            &[
                ("overcommit_memory", SYSCTL_OVERCOMMIT_MEMORY),
                ("overcommit_ratio", SYSCTL_OVERCOMMIT_RATIO),
                ("overcommit_kbytes", SYSCTL_OVERCOMMIT_KBYTES),
                ("max_map_count", SYSCTL_MAX_MAP_COUNT),
                ("pid_max", SYSCTL_PID_MAX),
                ("threads-max", SYSCTL_THREADS_MAX),
                ("sched_rt_runtime_us", SYSCTL_SCHED_RT_RUNTIME),
                ("ftrace_enabled", SYSCTL_FTRACE_ENABLED),
            ][..]
        );
        for (name, kind) in SYSCTL_FILES {
            assert!(name.len() <= 24, "{name}: longer than the three name words");
            assert_eq!(sysctl_kind(name.len(), name_words(name.as_bytes())), kind);
        }
    }
}
