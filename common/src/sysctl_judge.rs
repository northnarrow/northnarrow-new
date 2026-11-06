//! Lot 280a: the guarded sysctls judged on the value the kernel will apply.
//!
//! Lot 273d's write deny (`file_permission`) reads the bytes of a write of a
//! guarded sysctl from the writer's memory before the kernel copies them: a
//! second thread of the writer can change them in between (the residual it
//! declared, measured in its lab: 111 of 2,000 flipped writes got in). The
//! `cgroup/sysctl` program on the root cgroup runs after the kernel's copy
//! (`proc_sys_call_handler`: the buffer is duplicated, then the program,
//! then the handler parses that same copy) and reads it with
//! `bpf_sysctl_get_new_value`; `bpf_strtol` in base 0 reads it as the
//! kernel does (`proc_get_long` → `strtoul_lenient(…, 0, …)`: a leading `0`
//! is octal, `0x` hexadecimal, leading blanks skipped). The verdict is this
//! module's, one table with the write deny's (`cgroup_limits::
//! sysctl_value_harmful`), so the host's tests judge what both programs
//! decide.
//!
//! The signed per-sysctl opt-out (the per-rule policy's `sysctl-allow`
//! line): a value or a range the operator allows for one guarded sysctl,
//! outside a window too — tuned's `realtime` profile writes
//! `kernel.sched_rt_runtime_us = -1`, which neither path let through. The
//! agent writes it to the kernel only from a policy whose signature it
//! verified, bound to its boot's session nonce; a write it lets through
//! that would otherwise be refused is recorded.

use crate::cgroup_limits::{
    sysctl_refuses_every_write, sysctl_value_harmful, SYSCTL_FTRACE_ENABLED, SYSCTL_MAX_MAP_COUNT,
    SYSCTL_NONE, SYSCTL_OVERCOMMIT_KBYTES, SYSCTL_OVERCOMMIT_MEMORY, SYSCTL_OVERCOMMIT_RATIO,
    SYSCTL_PID_MAX, SYSCTL_SCHED_RT_PERIOD, SYSCTL_SCHED_RT_RUNTIME, SYSCTL_THREADS_MAX,
};

/// The guarded sysctls by the name `bpf_sysctl_get_name` gives without
/// `BPF_F_SYSCTL_BASE_NAME` (their path under `/proc/sys`), and by the name
/// `sysctl(8)` and the policy use, with their kinds.
pub const SYSCTL_PATHS: [(&str, &str, u8); 9] = [
    (
        "vm/overcommit_memory",
        "vm.overcommit_memory",
        SYSCTL_OVERCOMMIT_MEMORY,
    ),
    (
        "vm/overcommit_ratio",
        "vm.overcommit_ratio",
        SYSCTL_OVERCOMMIT_RATIO,
    ),
    (
        "vm/overcommit_kbytes",
        "vm.overcommit_kbytes",
        SYSCTL_OVERCOMMIT_KBYTES,
    ),
    ("vm/max_map_count", "vm.max_map_count", SYSCTL_MAX_MAP_COUNT),
    ("kernel/pid_max", "kernel.pid_max", SYSCTL_PID_MAX),
    (
        "kernel/threads-max",
        "kernel.threads-max",
        SYSCTL_THREADS_MAX,
    ),
    (
        "kernel/sched_rt_runtime_us",
        "kernel.sched_rt_runtime_us",
        SYSCTL_SCHED_RT_RUNTIME,
    ),
    (
        "kernel/ftrace_enabled",
        "kernel.ftrace_enabled",
        SYSCTL_FTRACE_ENABLED,
    ),
    (
        "kernel/sched_rt_period_us",
        "kernel.sched_rt_period_us",
        SYSCTL_SCHED_RT_PERIOD,
    ),
];

/// The name buffer the program reads (`bpf_sysctl_get_name` writes the
/// name and its NUL): a longer name is `-E2BIG`, never one of ours (the
/// longest, `kernel/sched_rt_runtime_us`, is 26 bytes).
pub const SYSCTL_PATH_MAX: usize = 32;

/// `name` in four little-endian words, zero past its end (at most
/// [`SYSCTL_PATH_MAX`] bytes): what the program compares, read into a
/// zeroed buffer.
pub const fn path_words(name: &[u8]) -> [u64; 4] {
    let mut w = [0u64; 4];
    let mut i = 0;
    while i < name.len() && i < SYSCTL_PATH_MAX {
        w[i / 8] |= (name[i] as u64) << ((i % 8) * 8);
        i += 1;
    }
    w
}

const fn sysctl_path_words() -> [(usize, [u64; 4], u8); SYSCTL_PATHS.len()] {
    let mut out = [(0usize, [0u64; 4], SYSCTL_NONE); SYSCTL_PATHS.len()];
    let mut i = 0;
    while i < SYSCTL_PATHS.len() {
        let (path, _, kind) = SYSCTL_PATHS[i];
        out[i] = (path.len(), path_words(path.as_bytes()), kind);
        i += 1;
    }
    out
}

/// [`SYSCTL_PATHS`] as the program compares them.
pub const SYSCTL_PATH_WORDS: [(usize, [u64; 4], u8); SYSCTL_PATHS.len()] = sysctl_path_words();

/// The kind of the sysctl whose path is `len` bytes packed in `w`
/// ([`path_words`]), or [`SYSCTL_NONE`].
#[inline(always)]
pub fn sysctl_path_kind(len: usize, w: [u64; 4]) -> u8 {
    let mut i = 0;
    while i < SYSCTL_PATH_WORDS.len() {
        let (l, n, kind) = SYSCTL_PATH_WORDS[i];
        if l == len && n[0] == w[0] && n[1] == w[1] && n[2] == w[2] && n[3] == w[3] {
            return kind;
        }
        i += 1;
    }
    SYSCTL_NONE
}

/// The kind of a guarded sysctl named as `sysctl(8)` names it
/// (`kernel.pid_max`), or [`SYSCTL_NONE`].
pub fn kind_of_name(name: &str) -> u8 {
    let mut i = 0;
    while i < SYSCTL_PATHS.len() {
        let (_, dotted, kind) = SYSCTL_PATHS[i];
        if dotted == name {
            return kind;
        }
        i += 1;
    }
    SYSCTL_NONE
}

/// The `sysctl(8)` name of a kind (`None` for [`SYSCTL_NONE`] or an unknown
/// byte).
pub fn name_of_kind(kind: u8) -> Option<&'static str> {
    let mut i = 0;
    while i < SYSCTL_PATHS.len() {
        let (_, dotted, k) = SYSCTL_PATHS[i];
        if k == kind {
            return Some(dotted);
        }
        i += 1;
    }
    None
}

/// The opt-out map's slots, indexed by kind.
pub const SYSCTL_OPTOUT_SLOTS: u32 = 16;

/// One slot of the opt-out map (`SYSCTL_OPTOUT`, indexed by kind): the
/// values `min..=max` the signed policy allows, while `armed` and written
/// for this boot's session (a slot an earlier agent wrote is dead after a
/// restart until the new one writes it again).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SysctlOptOut {
    pub min: i64,
    pub max: i64,
    pub session: u32,
    pub armed: u32,
}

impl SysctlOptOut {
    /// The range in force for `session`, `None` when the slot is not
    /// armed or not this session's.
    #[inline(always)]
    pub const fn live(&self, session: u32) -> Option<(i64, i64)> {
        if self.armed != 0 && self.session == session {
            Some((self.min, self.max))
        } else {
            None
        }
    }
}

/// What a write of a guarded sysctl gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SysctlVerdict {
    /// Let through: harmless, or by the agent's family or a window.
    Allow,
    /// Refused (`EPERM`), signed.
    Refuse,
    /// Let through by the signed opt-out, which alone allowed it: recorded.
    OptedOut,
}

/// The kinds the opt-out may name: every guarded sysctl but
/// `kernel.ftrace_enabled` — 0 blinds the agent itself (the BPF
/// trampolines stop, its deny hooks among them), and no other value is a
/// tuning anyone needs. `Err` says why.
pub const fn opt_out_allowed(kind: u8) -> Result<(), &'static str> {
    match kind {
        SYSCTL_NONE => Err("not a sysctl the agent guards"),
        SYSCTL_FTRACE_ENABLED => Err(
            "kernel.ftrace_enabled is never opted out: 0 stops the BPF trampolines, the \
             agent's deny hooks among them (a window lets it through)",
        ),
        _ => Ok(()),
    }
}

/// The verdict on `value`, the integer the kernel will store in the sysctl
/// of `kind` (`None`: not read, not an integer, past 63 characters or
/// past `i64`), outside the agent's family and a window: refused when it
/// is not known, when it is harmful (`sysctl_value_harmful`) and when the
/// sysctl's every write is refused (`sysctl_refuses_every_write`) — unless
/// `optout` (the signed range in force) holds it, then let through and
/// recorded. A harmless value in the range is plain `Allow`.
#[inline(always)]
pub const fn sysctl_value_verdict(
    kind: u8,
    value: Option<i64>,
    optout: Option<(i64, i64)>,
) -> SysctlVerdict {
    let v = match value {
        Some(v) => v,
        None => return SysctlVerdict::Refuse,
    };
    if !sysctl_refuses_every_write(kind) && !sysctl_value_harmful(kind, v) {
        return SysctlVerdict::Allow;
    }
    match optout {
        Some((min, max)) if min <= v && v <= max && kind != SYSCTL_FTRACE_ENABLED => {
            SysctlVerdict::OptedOut
        }
        _ => SysctlVerdict::Refuse,
    }
}

/// The `cgroup/sysctl` program's verdict on a write of the guarded sysctl
/// of `kind` (`SYSCTL_NONE`: not one, let through): the agent's family
/// and a window pass (`caller_may`: the identity every guarded write is
/// let through by, the round's own restore among them), the others by
/// [`sysctl_value_verdict`] on the kernel's copy.
#[inline(always)]
pub const fn sysctl_kernel_verdict(
    kind: u8,
    caller_may: bool,
    value: Option<i64>,
    optout: Option<(i64, i64)>,
) -> SysctlVerdict {
    if kind == SYSCTL_NONE || caller_may {
        return SysctlVerdict::Allow;
    }
    sysctl_value_verdict(kind, value, optout)
}

/// The write deny's verdict (`file_permission`, lot 273d), with the
/// opt-out: as [`sysctl_kernel_verdict`], except that a sysctl whose
/// every write is refused is refused without reading the write when no
/// opt-out names it (nothing for a second thread to race), and that the
/// bytes are read from the writer (`written`, decimal only: a spelling the
/// kernel reads in another base is refused, `cgroup_limits::parse_i64`).
#[inline(always)]
pub fn sysctl_write_verdict(
    kind: u8,
    caller_may: bool,
    optout: Option<(i64, i64)>,
    written: impl FnOnce() -> Option<crate::cgroup_limits::LimitValue>,
) -> SysctlVerdict {
    if kind == SYSCTL_NONE || caller_may {
        return SysctlVerdict::Allow;
    }
    if sysctl_refuses_every_write(kind) && optout.is_none() {
        return SysctlVerdict::Refuse;
    }
    let value = match written() {
        Some(w) => crate::cgroup_limits::parse_i64(&w),
        None => None,
    };
    sysctl_value_verdict(kind, value, optout)
}

/// The record of a write the `cgroup/sysctl` program judged (on
/// `FS_PROTECT_EVENTS`, `wire::FS_OP_SYSCTL_VALUE` /
/// `wire::FS_OP_SYSCTL_OPT_OUT`): `target_dev` = the kind, with this bit
/// when the value was not read as an integer; `target_ino` = the value.
pub const SYSCTL_RECORD_UNREAD: u64 = 1 << 8;

/// The record's `target_dev`.
#[inline(always)]
pub const fn record_dev(kind: u8, read: bool) -> u64 {
    kind as u64 | if read { 0 } else { SYSCTL_RECORD_UNREAD }
}

/// A record's kind and value (`None`: not read), from its `target_dev` and
/// `target_ino`.
pub const fn record_of(target_dev: u64, target_ino: u64) -> (u8, Option<i64>) {
    let kind = (target_dev & 0xff) as u8;
    if target_dev & SYSCTL_RECORD_UNREAD != 0 {
        (kind, None)
    } else {
        (kind, Some(target_ino as i64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cgroup_limits::{limit_value, SYSCTL_FILES};

    fn k(path: &str) -> u8 {
        sysctl_path_kind(path.len(), path_words(path.as_bytes()))
    }

    /// The paths the program compares: every guarded sysctl, by its full
    /// path only (a base name, another directory's file, a prefix, a
    /// longer name are none of them).
    #[test]
    fn the_program_knows_the_guarded_sysctls_by_their_path() {
        for (path, dotted, kind) in SYSCTL_PATHS {
            assert_eq!(k(path), kind, "{path}");
            assert!(path.len() < SYSCTL_PATH_MAX, "{path}");
            assert_eq!(kind_of_name(dotted), kind);
            assert_eq!(name_of_kind(kind), Some(dotted));
            assert_eq!(dotted.replace('.', "/"), path);
            // the write deny's base name is the same file
            let base = path.rsplit('/').next().unwrap();
            assert!(SYSCTL_FILES.contains(&(base, kind)), "{base}");
        }
        assert_eq!(SYSCTL_PATHS.len(), SYSCTL_FILES.len());
        for other in [
            "pid_max",
            "kernel/pid_max2",
            "kernel/pid_ma",
            "net/pid_max",
            "vm/pid_max",
            "kernel/overcommit_memory",
            "kernel/ftrace_dump_on_oops",
            "kernel/sched_rt_runtime_u",
            "",
        ] {
            assert_eq!(k(other), SYSCTL_NONE, "{other}");
        }
        // the words past the name are zero: the same name read in a
        // buffer with a stale byte after its NUL is not a match
        let mut w = path_words(b"kernel/pid_max");
        w[3] |= 1 << 56;
        assert_eq!(sysctl_path_kind(14, w), SYSCTL_NONE);
        assert_eq!(kind_of_name("kernel/pid_max"), SYSCTL_NONE);
        assert_eq!(name_of_kind(SYSCTL_NONE), None);
        assert_eq!(name_of_kind(200), None);
    }

    /// Named test (lot 280a): a value the kernel reads in base 8 or 16
    /// below a floor is refused — the kernel's copy is read in base 0
    /// (`bpf_strtol`), so `040000` is judged as the 16384 the kernel
    /// stores, `0x4000` too; the write deny, which reads decimal only,
    /// refuses either spelling unread.
    #[test]
    fn an_octal_or_hex_value_below_a_floor_is_denied() {
        // what bpf_strtol(…, 0, …) gives for "040000", "0x4000", "0X7fff"
        for (spelling, base0) in [("040000", 0o40000), ("0x4000", 0x4000), ("0X7fff", 0x7fff)] {
            assert!(base0 < 32768, "{spelling}");
            assert_eq!(
                sysctl_kernel_verdict(SYSCTL_PID_MAX, false, Some(base0), None),
                SysctlVerdict::Refuse,
                "{spelling}"
            );
            // the write deny reads the bytes, decimal only: refused
            assert_eq!(
                sysctl_write_verdict(SYSCTL_PID_MAX, false, None, || limit_value(
                    spelling.as_bytes()
                )),
                SysctlVerdict::Refuse,
                "{spelling}"
            );
        }
        // the decimal it looks like is above the floor: judged as written
        // it would pass — that is the bug the base-0 read avoids
        assert_eq!(
            sysctl_kernel_verdict(SYSCTL_PID_MAX, false, Some(40000), None),
            SysctlVerdict::Allow
        );
        // above the floor in base 16: the kernel's copy lets it through
        assert_eq!(
            sysctl_kernel_verdict(SYSCTL_PID_MAX, false, Some(0x10000), None),
            SysctlVerdict::Allow
        );
        // max_map_count and threads-max alike
        assert_eq!(
            sysctl_kernel_verdict(SYSCTL_MAX_MAP_COUNT, false, Some(0o177777), None),
            SysctlVerdict::Allow
        );
        assert_eq!(
            sysctl_kernel_verdict(SYSCTL_THREADS_MAX, false, Some(0x1fff), None),
            SysctlVerdict::Refuse
        );
    }

    /// The program's verdict: the family and a window pass; a value not
    /// read is refused; ftrace_enabled and the RT period refused whatever
    /// they carry; the floors as the write deny's.
    #[test]
    fn the_kernel_copy_is_judged_by_the_shared_floors() {
        use SysctlVerdict::*;
        let v = |kind, value| sysctl_kernel_verdict(kind, false, value, None);
        assert_eq!(sysctl_kernel_verdict(SYSCTL_NONE, false, None, None), Allow);
        for (_, _, kind) in SYSCTL_PATHS {
            assert_eq!(sysctl_kernel_verdict(kind, true, None, None), Allow);
            assert_eq!(sysctl_kernel_verdict(kind, true, Some(0), None), Allow);
            assert_eq!(v(kind, None), Refuse, "{kind}");
        }
        assert_eq!(v(SYSCTL_FTRACE_ENABLED, Some(1)), Refuse);
        assert_eq!(v(SYSCTL_FTRACE_ENABLED, Some(0)), Refuse);
        assert_eq!(v(SYSCTL_SCHED_RT_PERIOD, Some(1_000_000)), Refuse);
        assert_eq!(v(SYSCTL_PID_MAX, Some(32767)), Refuse);
        assert_eq!(v(SYSCTL_PID_MAX, Some(32768)), Allow);
        assert_eq!(v(SYSCTL_PID_MAX, Some(4_194_304)), Allow);
        assert_eq!(v(SYSCTL_SCHED_RT_RUNTIME, Some(-1)), Refuse);
        assert_eq!(v(SYSCTL_SCHED_RT_RUNTIME, Some(950_000)), Allow);
        assert_eq!(v(SYSCTL_SCHED_RT_RUNTIME, Some(990_000)), Refuse);
        assert_eq!(v(SYSCTL_OVERCOMMIT_MEMORY, Some(2)), Refuse);
        assert_eq!(v(SYSCTL_OVERCOMMIT_MEMORY, Some(1)), Allow);
        assert_eq!(v(SYSCTL_OVERCOMMIT_RATIO, Some(49)), Refuse);
        assert_eq!(v(SYSCTL_OVERCOMMIT_RATIO, Some(50)), Allow);
        assert_eq!(v(SYSCTL_OVERCOMMIT_KBYTES, Some(0)), Allow);
        assert_eq!(v(SYSCTL_OVERCOMMIT_KBYTES, Some(1 << 20)), Allow);
        assert_eq!(v(SYSCTL_OVERCOMMIT_KBYTES, Some(1)), Refuse);
        assert_eq!(v(SYSCTL_MAX_MAP_COUNT, Some(65529)), Refuse);
        assert_eq!(v(SYSCTL_THREADS_MAX, Some(8192)), Allow);
    }

    /// Named test (lot 280a): the signed opt-out lets its range through and
    /// says so (`OptedOut`, recorded); outside its range, without it, or for
    /// a harmless value (plain `Allow`, nothing to record) it changes
    /// nothing; never for ftrace_enabled.
    #[test]
    fn the_opt_out_allows_its_range_and_is_recorded() {
        use SysctlVerdict::*;
        let rt = Some((-1, -1));
        assert_eq!(
            sysctl_kernel_verdict(SYSCTL_SCHED_RT_RUNTIME, false, Some(-1), rt),
            OptedOut
        );
        assert_eq!(
            sysctl_kernel_verdict(SYSCTL_SCHED_RT_RUNTIME, false, Some(-1), None),
            Refuse
        );
        assert_eq!(
            sysctl_kernel_verdict(SYSCTL_SCHED_RT_RUNTIME, false, Some(990_000), rt),
            Refuse
        );
        assert_eq!(
            sysctl_kernel_verdict(SYSCTL_SCHED_RT_RUNTIME, false, Some(950_000), rt),
            Allow
        );
        assert_eq!(
            sysctl_kernel_verdict(SYSCTL_SCHED_RT_RUNTIME, false, None, rt),
            Refuse
        );
        // a range, its ends included
        let pm = Some((4096, 32767));
        for (v, want) in [
            (4095, Refuse),
            (4096, OptedOut),
            (20000, OptedOut),
            (32767, OptedOut),
            (32768, Allow),
        ] {
            assert_eq!(
                sysctl_kernel_verdict(SYSCTL_PID_MAX, false, Some(v), pm),
                want,
                "{v}"
            );
        }
        // the RT period's every write: its range lets a value through
        assert_eq!(
            sysctl_kernel_verdict(
                SYSCTL_SCHED_RT_PERIOD,
                false,
                Some(500_000),
                Some((500_000, 500_000))
            ),
            OptedOut
        );
        // never ftrace_enabled, even with a slot
        assert_eq!(
            sysctl_kernel_verdict(SYSCTL_FTRACE_ENABLED, false, Some(0), Some((0, 0))),
            Refuse
        );
        assert!(opt_out_allowed(SYSCTL_FTRACE_ENABLED).is_err());
        assert!(opt_out_allowed(SYSCTL_NONE).is_err());
        for (_, _, kind) in SYSCTL_PATHS {
            if kind != SYSCTL_FTRACE_ENABLED {
                assert!(opt_out_allowed(kind).is_ok(), "{kind}");
            }
        }
        // the write deny honours the same slot (tuned's write passes it
        // too), reads the RT period's bytes only when a slot names it
        let mut read = false;
        assert_eq!(
            sysctl_write_verdict(SYSCTL_SCHED_RT_RUNTIME, false, rt, || limit_value(b"-1\n")),
            OptedOut
        );
        assert_eq!(
            sysctl_write_verdict(SYSCTL_SCHED_RT_PERIOD, false, None, || {
                read = true;
                limit_value(b"500000")
            }),
            Refuse
        );
        assert!(
            !read,
            "the RT period's write is refused unread without a slot"
        );
        assert_eq!(
            sysctl_write_verdict(
                SYSCTL_SCHED_RT_PERIOD,
                false,
                Some((500_000, 500_000)),
                || { limit_value(b"500000") }
            ),
            OptedOut
        );
        assert_eq!(
            sysctl_write_verdict(SYSCTL_PID_MAX, true, None, || None),
            Allow
        );
        assert_eq!(
            sysctl_write_verdict(SYSCTL_NONE, false, None, || None),
            Allow
        );
    }

    /// A slot is in force only armed and for this session.
    #[test]
    fn an_opt_out_slot_lives_for_its_session_only() {
        let s = SysctlOptOut {
            min: -1,
            max: -1,
            session: 7,
            armed: 1,
        };
        assert_eq!(s.live(7), Some((-1, -1)));
        assert_eq!(s.live(8), None);
        assert_eq!(SysctlOptOut { armed: 0, ..s }.live(7), None);
        assert_eq!(SysctlOptOut::default().live(0), None);
        assert_eq!(core::mem::size_of::<SysctlOptOut>(), 24);
    }

    /// The record carries the kind and the value, or that it was not read.
    #[test]
    fn a_record_carries_the_kind_and_the_value() {
        let dev = record_dev(SYSCTL_PID_MAX, true);
        assert_eq!(dev, SYSCTL_PID_MAX as u64);
        assert_eq!(record_of(dev, 16384), (SYSCTL_PID_MAX, Some(16384)));
        assert_eq!(record_of(dev, (-1i64) as u64), (SYSCTL_PID_MAX, Some(-1)));
        let unread = record_dev(SYSCTL_SCHED_RT_RUNTIME, false);
        assert_eq!(unread & SYSCTL_RECORD_UNREAD, SYSCTL_RECORD_UNREAD);
        assert_eq!(record_of(unread, 0), (SYSCTL_SCHED_RT_RUNTIME, None));
    }
}
