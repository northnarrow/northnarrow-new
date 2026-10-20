//! Wave 4, lab PR 223 (EXPERIMENTAL) — exec quarantine at first sight:
//! the kernel ↔ agent contract of the guard (design
//! `docs/design/EXEC_QUARANTINE.md`).
//!
//! The LSM exec sensor (`agent-ebpf/src/exec_lsm.rs`) classifies the file
//! of each binfmt pass: a file in a guarded location (a memfd, an unlinked
//! file, a memory-backed filesystem, a world-writable directory, `/tmp`,
//! `/var/tmp`, a home directory, a guarded mount) whose identity is not in
//! [`EXECQ_KNOWN`](self) becomes the exec's candidate. When the exec
//! succeeds, `sched_process_exec` — in the exec'ing task, after the point
//! of no return and before the task returns to user mode in the new image
//! — sends it `SIGSTOP` (`bpf_send_signal`) and emits an [`ExecqStopRaw`]:
//! the new image is held before its first instruction until the agent
//! resumes it (`SIGCONT`) or kills it.
//!
//! Every struct is `#[repr(C)]` with explicit padding; strict append-only.

use super::exe::ExeIdentityRaw;
use super::TASK_COMM_LEN;

/// `EXECQ_CONF` slots (an `Array<u64>`, written once by the agent before
/// the programs attach, then frozen).
pub mod conf_slot {
    /// [`super::mode`] value.
    pub const MODE: u32 = 0;
    /// The guarded classes ([`super::class`] bits).
    pub const CLASSES: u32 = 1;
    /// A stop needs an agent heartbeat younger than this (ns).
    pub const HEARTBEAT_MAX_NS: u32 = 2;
    /// Slots in the map.
    pub const SLOTS: u32 = 4;
}

/// `EXECQ_CONF[MODE]`.
pub mod mode {
    /// No candidate, no stop, no record (the default).
    pub const OFF: u64 = 0;
    /// Candidates are recorded and scanned while they run (no stop):
    /// `--exec-quarantine observe` and every detect-only agent.
    pub const OBSERVE: u64 = 1;
    /// Candidates are stopped before their first instruction.
    pub const ENFORCE: u64 = 2;
}

/// Guarded classes: why a file is a candidate (`ExecqStopRaw::class`).
/// Lab PR 226 split `/var/tmp` and `/dev/shm` out of `TMP` and `TMPFS`
/// (the exec policy gives them their own rules) and added the home of
/// another user; the exec quarantine guards them all by default, as
/// before.
pub mod class {
    /// A `memfd_create` file.
    pub const MEMFD: u32 = 1 << 0;
    /// Unlinked (`i_nlink == 0`) or an `O_TMPFILE`.
    pub const DELETED: u32 = 1 << 1;
    /// On a memory-backed filesystem (tmpfs, hugetlbfs, ramfs).
    pub const TMPFS: u32 = 1 << 2;
    /// Its directory is writable by every user (`S_IWOTH`).
    pub const WORLD_WRITABLE_DIR: u32 = 1 << 3;
    /// Under `/tmp` (the task's own view), or on a filesystem mounted at
    /// `/tmp`.
    pub const TMP: u32 = 1 << 4;
    /// Under `/home` or `/root` (the task's own view), or on a filesystem
    /// mounted there.
    pub const HOME: u32 = 1 << 5;
    /// On a filesystem the agent mounted guarded (`EXECQ_ROOTS`: a separate
    /// `/home`, `/tmp`, `/var/tmp`, `/dev/shm` or `/run/user/*`).
    pub const GUARDED_MOUNT: u32 = 1 << 6;
    /// Lab PR 226: under `/dev/shm`, or on the filesystem mounted there.
    pub const DEV_SHM: u32 = 1 << 7;
    /// Lab PR 226: under `/var/tmp`, or on a filesystem mounted there
    /// (`TMP` until lab PR 226).
    pub const VAR_TMP: u32 = 1 << 8;
    /// Lab PR 226: in a home directory (`HOME`) and owned by a user who is
    /// neither the caller (real uid) nor root: code another account
    /// controls.
    pub const OTHER_HOME: u32 = 1 << 9;
    /// Classes (bits).
    pub const COUNT: u32 = 10;
    /// Every class.
    pub const ALL: u32 = MEMFD
        | DELETED
        | TMPFS
        | WORLD_WRITABLE_DIR
        | TMP
        | HOME
        | GUARDED_MOUNT
        | DEV_SHM
        | VAR_TMP
        | OTHER_HOME;
}

/// `EXECQ_ROOTS` value bits (lab PR 226): which guarded point a mounted
/// filesystem's root is at, so a file on it gets that point's class too.
pub mod root_kind {
    /// A guarded mount ([`super::class::GUARDED_MOUNT`]).
    pub const GUARDED: u32 = 1 << 0;
    /// Mounted at (or below) `/tmp`.
    pub const TMP: u32 = 1 << 1;
    /// At (or below) `/var/tmp`.
    pub const VAR_TMP: u32 = 1 << 2;
    /// At (or below) `/dev/shm`.
    pub const DEV_SHM: u32 = 1 << 3;
    /// At (or below) `/home` or `/root`.
    pub const HOME: u32 = 1 << 4;
}

/// `ExecqStopRaw::flags` / `ExecqCandRaw::flags`.
pub mod stop_flags {
    /// The candidate is an interpreter pass (pass 1+): the file the
    /// process runs.
    pub const INTERP_PASS: u32 = 1 << 0;
    /// The candidate is pass 0 and a later pass ran: a `#!` script (or a
    /// binfmt_misc input), the image is its interpreter.
    pub const SCRIPT: u32 = 1 << 1;
    /// Observe mode: not stopped by design.
    pub const OBSERVE: u32 = 1 << 2;
    /// Not stopped: the agent's heartbeat was stale (fail-open).
    pub const HEARTBEAT_STALE: u32 = 1 << 3;
    /// `bpf_send_signal` failed (`stop_rc`): not stopped.
    pub const SIGNAL_FAILED: u32 = 1 << 4;
    /// The ctime offsets are absent on this kernel: the identity cache
    /// cannot vouch for the content, every exec of the file is a candidate.
    pub const NO_CTIME: u32 = 1 << 5;
    /// Lab PR 226: the candidate is a `#!` script (or a binfmt_misc input)
    /// and the guard enforces: refused at the interpreter's pass
    /// (`-EACCES`), not stopped. The interpreter opens the script by its
    /// path once it runs, so a scan made while it is held cannot vouch for
    /// what it reads (the file can be rewritten or replaced in between).
    pub const SCRIPT_REFUSED: u32 = 1 << 6;
}

/// `EXECQ_COUNTERS` slots (per-CPU `u64`, summed by the agent).
pub mod counter {
    /// Candidates stopped.
    pub const STOPPED: u32 = 0;
    /// Candidates seen in observe mode.
    pub const OBSERVED: u32 = 1;
    /// Execs skipped: the identity was already judged.
    pub const KNOWN_SKIP: u32 = 2;
    /// Candidates not stopped: heartbeat stale.
    pub const STALE: u32 = 3;
    /// Candidates not stopped: the ring was full.
    pub const RING_FULL: u32 = 4;
    /// Candidates not stopped: `bpf_send_signal` failed.
    pub const SIGNAL_FAILED: u32 = 5;
    /// Candidates the `EXECQ_CAND` map could not hold.
    pub const CAND_DROPPED: u32 = 6;
    /// Lab PR 226: scripts refused at exec (enforce mode).
    pub const SCRIPT_REFUSED: u32 = 7;
    /// Slots in the map.
    pub const SLOTS: u32 = 8;
}

/// Key of `EXECQ_KNOWN` and `EXECQ_ROOTS`: an inode as the exec sensor
/// keys it (kernel `dev_t`, as `ExeIdentityRaw::dev`).
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct ExecqKey {
    pub dev: u64,
    pub ino: u64,
}

/// `EXECQ_KNOWN` value: the content stamp the agent judged. A later exec
/// of the same inode skips the stop only while ctime and size are the
/// ones judged (any write, truncation or `chmod` moves ctime).
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct ExecqKnown {
    pub ctime_sec: i64,
    pub size: i64,
    pub ctime_nsec: u32,
    /// [`known_verdict`] value.
    pub verdict: u32,
}

/// `ExecqKnown::verdict`.
pub mod known_verdict {
    /// Scanned clean (or trusted by an allow entry or the package database).
    pub const CLEAN: u32 = 1;
    /// Suspicious, resumed by the policy: recorded once, not stopped again.
    pub const RESUMED: u32 = 2;
}

/// `EXECQ_STOPPED` value (pinned): a process the kernel stopped and the
/// agent has not decided on yet. A restarted agent resumes what its
/// predecessor left.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct ExecqStopped {
    /// `task_struct.start_time` (CLOCK_MONOTONIC ns): the PID-reuse key.
    pub start_ns: u64,
    /// When it was stopped (CLOCK_MONOTONIC ns).
    pub stop_ns: u64,
}

/// `EXECQ_CAND` value: the candidate of an exec in progress, keyed by the
/// exec'ing `task_struct`, from `bprm_check_security` to
/// `sched_process_exec`.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct ExecqCandRaw {
    pub ctime_sec: i64,
    pub size: i64,
    pub ctime_nsec: u32,
    pub class: u32,
    pub flags: u32,
    pub _pad: u32,
    pub exe: ExeIdentityRaw,
}

impl ExecqCandRaw {
    pub const fn zeroed() -> Self {
        Self {
            ctime_sec: 0,
            size: 0,
            ctime_nsec: 0,
            class: 0,
            flags: 0,
            _pad: 0,
            exe: ExeIdentityRaw::zeroed(),
        }
    }
}

/// One candidate exec, stopped (or observed), as the kernel reports it on
/// the `EXECQ_EVENTS` ring. 640 bytes, no implicit padding.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct ExecqStopRaw {
    /// tgid (the process).
    pub pid: u32,
    /// The thread that exec'd (the only one left after `de_thread`).
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    /// `bpf_send_signal`'s return (0: stopped; negative errno).
    pub stop_rc: i32,
    /// When the stop was sent (CLOCK_MONOTONIC ns).
    pub timestamp_ns: u64,
    /// `task_struct.start_time` (CLOCK_MONOTONIC ns): the PID-reuse key,
    /// the one `ProcessSpawnRaw::start_ns` carries.
    pub start_ns: u64,
    /// The candidate file's ctime and size when the exec opened it.
    pub ctime_sec: i64,
    pub size: i64,
    pub ctime_nsec: u32,
    /// [`class`] bits.
    pub class: u32,
    /// [`stop_flags`] bits.
    pub flags: u32,
    pub _pad: u32,
    pub comm: [u8; TASK_COMM_LEN],
    /// The candidate file (the pass that made it one).
    pub exe: ExeIdentityRaw,
}

impl ExecqStopRaw {
    pub const fn zeroed() -> Self {
        Self {
            pid: 0,
            tid: 0,
            ppid: 0,
            uid: 0,
            gid: 0,
            stop_rc: 0,
            timestamp_ns: 0,
            start_ns: 0,
            ctime_sec: 0,
            size: 0,
            ctime_nsec: 0,
            class: 0,
            flags: 0,
            _pad: 0,
            comm: [0; TASK_COMM_LEN],
            exe: ExeIdentityRaw::zeroed(),
        }
    }

    /// Whether the kernel stopped the process (enforce mode, signal sent).
    pub const fn stopped(&self) -> bool {
        self.flags
            & (stop_flags::OBSERVE
                | stop_flags::SIGNAL_FAILED
                | stop_flags::HEARTBEAT_STALE
                | stop_flags::SCRIPT_REFUSED)
            == 0
            && self.stop_rc == 0
    }
}

/// Class names, for records and logs.
#[cfg(feature = "std")]
pub fn class_names(bits: u32) -> alloc::vec::Vec<&'static str> {
    let mut v = alloc::vec::Vec::new();
    for (bit, name) in [
        (class::MEMFD, "memfd"),
        (class::DELETED, "deleted"),
        (class::TMPFS, "tmpfs"),
        (class::WORLD_WRITABLE_DIR, "world_writable_dir"),
        (class::TMP, "tmp"),
        (class::HOME, "home"),
        (class::GUARDED_MOUNT, "guarded_mount"),
        (class::DEV_SHM, "dev_shm"),
        (class::VAR_TMP, "var_tmp"),
        (class::OTHER_HOME, "other_home"),
    ] {
        if bits & bit != 0 {
            v.push(name);
        }
    }
    v
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn layouts_are_fixed() {
        assert_eq!(core::mem::size_of::<ExecqKey>(), 16);
        assert_eq!(core::mem::size_of::<ExecqKnown>(), 24);
        assert_eq!(core::mem::size_of::<ExecqStopped>(), 16);
        assert_eq!(core::mem::size_of::<ExecqCandRaw>(), 32 + 552);
        assert_eq!(core::mem::size_of::<ExecqStopRaw>(), 640);
        assert_eq!(core::mem::offset_of!(ExecqStopRaw, exe), 88);
        assert_eq!(core::mem::align_of::<ExecqStopRaw>(), 8);
    }

    #[test]
    fn stopped_needs_enforce_and_a_sent_signal() {
        let mut r = ExecqStopRaw::zeroed();
        assert!(r.stopped());
        r.flags = stop_flags::OBSERVE;
        assert!(!r.stopped());
        r.flags = stop_flags::SCRIPT;
        assert!(r.stopped());
        r.stop_rc = -1;
        assert!(!r.stopped());
        // lab PR 226: a refused script was never stopped
        r.stop_rc = 0;
        r.flags = stop_flags::SCRIPT | stop_flags::SCRIPT_REFUSED;
        assert!(!r.stopped());
    }

    #[test]
    fn class_names_follow_the_bits() {
        assert_eq!(class_names(class::MEMFD | class::HOME), ["memfd", "home"]);
        assert_eq!(class_names(class::ALL).len(), class::COUNT as usize);
        assert_eq!(class::ALL, (1 << class::COUNT) - 1);
        assert_eq!(
            class_names(class::DEV_SHM | class::VAR_TMP | class::OTHER_HOME),
            ["dev_shm", "var_tmp", "other_home"]
        );
        assert!(class_names(0).is_empty());
    }
}
