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

/// Lot 318 (the review of #538): whether a filesystem type's name, its
/// first 16 bytes as two little-endian words (the bytes after its NUL zero),
/// is `virtiofs` — which shares `FUSE_SUPER_MAGIC` with `fuse` and
/// `fuseblk` and is not a user's FUSE mount (a VM's or a Kata container's
/// shared directory). The exec guards' kernel half reads it from
/// `sb->s_type->name`; the agent's mount table reader leaves `virtiofs` out
/// of FUSE by its type field alike.
pub const fn is_virtiofs_name(w0: u64, w1: u64) -> bool {
    w0 == u64::from_le_bytes(*b"virtiofs") && w1 & 0xff == 0
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
    /// Lot 317 (third bug hunt, review F3): not stopped — `EXECQ_STOPPED`
    /// could not name the process (the map full). The kernel stops only a
    /// process the map names, so that the agent's stop, its crash's next
    /// start and the boot's recovery can always resume it.
    pub const MAP_FULL: u32 = 1 << 7;
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
    /// Lot 317: candidates not stopped — `EXECQ_STOPPED` was full.
    pub const MAP_FULL: u32 = 8;
    /// The re-check of #547 (G5): the oldest candidates removed for a newer
    /// one, the candidates' map full — their execs run unheld.
    pub const CAND_EVICTED: u32 = 9;
    /// Slots in the map.
    pub const SLOTS: u32 = 10;
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
    /// The review of #547 (F4; the re-check, G5): the share of the
    /// candidates' map this one takes (`EXECQ_CAND_UIDS`) — the caller's
    /// [`share_key`] (lot 332: its uid, or its user namespace's creator or
    /// container); [`OVERFLOW_SHARE`] when the shares' map could not hold a
    /// row for it.
    pub uid: u32,
    /// The review of #547 (F4): the pass's inode (its address), by which a
    /// failed exec's candidate is found and removed when the kernel frees
    /// the exec's file.
    pub inode: u64,
    /// The re-check of #547 (G5): when it was made (`bpf_ktime_get_ns`), by
    /// which the oldest goes first when the map is full (lot 332: found by
    /// walking the map).
    pub at: u64,
    pub exe: ExeIdentityRaw,
}

/// The key of a task's share of the maps whose entries outlive a run (the
/// quarantine's candidates, the FIM sensor's task buffers): the account the
/// task's work is held to, which the task cannot choose.
///
/// - `level` 0, the initial user namespace: its real uid `uid` (the
///   kernel's, in that namespace). Lot 332 (the re-check 2 of #547, G5): it
///   was the login uid there, and a task whose login uid is unset — a
///   service, a container under a root daemon, where a foothold lands —
///   sets it to any value without a privilege (`audit_set_loginuid_perm`),
///   so each child of one service took a share of its own.
/// - In a user namespace, keyed by its outermost ancestor below the initial
///   one (the one a container runtime or `unshare -U` made): `owner`, the
///   account that created it, when that is not root — a rootless
///   container's subuids (`/etc/subuid`), its nested namespaces included,
///   are its user's, as the re-check of #547 asked; `inum`, that
///   namespace's inode number, when root made it (a system container:
///   LXD, a remapping docker), one share per container, whatever uid in its
///   range a process takes. The creator is set by the kernel when the
///   namespace is made, and nesting cannot reach past it.
///
/// Never [`OVERFLOW_SHARE`].
pub const fn share_key(uid: u32, level: u32, owner: u32, inum: u32) -> u32 {
    let k = if level == 0 {
        uid
    } else if owner != 0 {
        owner
    } else {
        inum
    };
    if k == OVERFLOW_SHARE {
        OVERFLOW_SHARE - 1
    } else {
        k
    }
}

/// The deepest user namespace below the initial one (the kernel refuses a
/// 33rd level, `create_user_ns`): the share key's walk to the outermost
/// ancestor takes at most this many steps.
pub const USERNS_MAX_LEVEL: u32 = 33;

/// The re-check of #547 (G5): the share of the keys the shares' map has no
/// row for (it is full): one row, under the same cap, held apart.
pub const OVERFLOW_SHARE: u32 = u32::MAX;

/// Lot 332: the rows of a shares map's array (`EXECQ_CAND_OVERFLOW`,
/// `OPEN_TASK_OVERFLOW`): the [`OVERFLOW_SHARE`] row, and the total of every
/// share's entries (the global cap, [`share_admits`]).
pub const OVERFLOW_ROW: u32 = 0;
pub const TOTAL_ROW: u32 = 1;
pub const SHARE_ROWS: u32 = 2;

/// Lot 332 (the re-check 2 of #547, G5): the global cap of a map of
/// `capacity` entries shared in shares of `per_share` — one share's room is
/// kept back: past the cap, only a share holding fewer than
/// [`share_floor`] entries takes one more, so the shares that fill the
/// rest (four of 1024 candidates filled 4096) leave room for 64 others.
pub const fn global_cap(capacity: u64, per_share: u64) -> u64 {
    capacity - per_share
}

/// The entries a share takes past the global cap ([`global_cap`]): a 64th
/// of a share.
pub const fn share_floor(per_share: u64) -> u64 {
    per_share / 64
}

/// Whether a share holding `own` entries takes one more while every share
/// together holds `total`: below its own cap, and below the global cap or
/// below the floor.
pub const fn share_admits(own: u64, total: u64, per_share: u64, global: u64, floor: u64) -> bool {
    own < per_share && (total < global || own < floor)
}

impl ExecqCandRaw {
    pub const fn zeroed() -> Self {
        Self {
            ctime_sec: 0,
            size: 0,
            ctime_nsec: 0,
            class: 0,
            flags: 0,
            uid: 0,
            inode: 0,
            at: 0,
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
                | stop_flags::SCRIPT_REFUSED
                | stop_flags::MAP_FULL)
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

    /// The re-check of #547 (G5): a login's processes share one row, the
    /// container subuids of a rootless runtime (`/etc/subuid`) included;
    /// a service is its uid's. Lot 332: the inputs are the kernel's — the
    /// uid, the user namespace's depth, the creator and inode of its
    /// outermost ancestor — no longer the login uid, which an unset task
    /// sets to anything.
    #[test]
    fn a_login_s_subuids_share_one_row() {
        let login = 1000;
        // the login's own processes (initial namespace), its rootless
        // container's subuids (a namespace it made), their nested
        // namespaces (the outermost is still its)
        let rows: Vec<u32> = (0..6)
            .map(|i| share_key(100_000 + i * 65_536, 1, login, 0xF000_0010))
            .chain([
                share_key(login, 0, 0, 0),
                share_key(100_000, 3, login, 0xF000_0010),
            ])
            .collect();
        assert!(rows.iter().all(|r| *r == login), "{rows:?}");
        // services: their own uid each
        assert_eq!(share_key(33, 0, 0, 0), 33);
        assert_eq!(share_key(0, 0, 0, 0), 0);
        assert_ne!(share_key(33, 0, 0, 0), share_key(108, 0, 0, 0));
        // no key is the overflow row's
        assert_ne!(share_key(65_534, 0, 0, 0), OVERFLOW_SHARE);
        assert_ne!(share_key(u32::MAX, 0, 0, 0), OVERFLOW_SHARE);
        assert_ne!(share_key(5, 1, 0, u32::MAX), OVERFLOW_SHARE);
    }

    /// Lot 332 (the re-check 2 of #547, G5): a service's children cannot
    /// spread over shares. The login uid is not an input any more: a task
    /// with none set it to anything without a privilege, one value per
    /// child. What a task can change is its uid only with a privilege, and
    /// a namespace it makes is held to it (its creator); a system
    /// container is one share whatever uid in its range a process takes.
    #[test]
    fn a_service_s_children_cannot_choose_their_share() {
        // www-data's children, whatever login uid each wrote, and the
        // namespaces they make (`unshare -U`: their creator is www-data)
        let children: Vec<u32> = (0..64)
            .map(|_| share_key(33, 0, 0, 0))
            .chain((1..=32).map(|lvl| share_key(33, lvl, 33, 0xF000_1000 + lvl)))
            .collect();
        assert!(children.iter().all(|k| *k == 33), "{children:?}");
        // a system container: every uid in its range is one share, the
        // container's (its namespace's inode); another container another
        let c1: Vec<u32> = (0..65_536u32)
            .step_by(4096)
            .map(|u| share_key(1_000_000 + u, 1, 0, 0xF000_0042))
            .collect();
        assert!(c1.iter().all(|k| *k == 0xF000_0042), "{c1:?}");
        assert_ne!(
            share_key(1_000_000, 1, 0, 0xF000_0042),
            share_key(1_065_536, 1, 0, 0xF000_0043)
        );
    }

    /// Lot 332 (the re-check 2 of #547, G5): the global cap — one share's
    /// room kept back. Four greedy shares no longer fill the map: past the
    /// cap they take nothing more, and 64 others still take their floor.
    #[test]
    fn greedy_shares_leave_room_for_others() {
        let (cap, per) = (4096u64, 1024u64);
        let (global, floor) = (global_cap(cap, per), share_floor(per));
        assert_eq!((global, floor), (3072, 16));
        // each share alone: up to its cap
        assert!(share_admits(per - 1, 0, per, global, floor));
        assert!(!share_admits(per, 0, per, global, floor));
        // greedy shares take until the global cap
        let mut total = 0u64;
        let mut greedy = [0u64; 8];
        for g in greedy.iter_mut() {
            while share_admits(*g, total, per, global, floor) {
                *g += 1;
                total += 1;
            }
        }
        // three reach their cap, the global cap with them; the others take
        // only their floor
        assert_eq!(greedy[..3], [per, per, per]);
        assert_eq!(greedy[3..], [floor; 5], "{greedy:?}");
        assert_eq!(total, global + 5 * floor);
        // past it, a share holding its floor or more takes nothing, and
        // each fresh one takes its floor: 64 shares in all fit in the room
        // kept back
        assert!(!share_admits(floor, total, per, global, floor));
        assert!(!share_admits(per - 1, total, per, global, floor));
        let mut fresh = 0u64;
        while total < cap {
            let mut own = 0u64;
            while share_admits(own, total, per, global, floor) {
                own += 1;
                total += 1;
            }
            assert_eq!(own, floor);
            fresh += 1;
        }
        assert_eq!(fresh + 5, 64);
        assert_eq!(total, cap, "the map's room exactly");
        // the FIM buffers' map
        assert_eq!(global_cap(65_536, 16_384), 49_152);
        assert_eq!(share_floor(16_384), 256);
    }

    #[test]
    fn layouts_are_fixed() {
        assert_eq!(core::mem::size_of::<ExecqKey>(), 16);
        assert_eq!(core::mem::size_of::<ExecqKnown>(), 24);
        assert_eq!(core::mem::size_of::<ExecqStopped>(), 16);
        // the review of #547 (F4): the inode's address added (kernel only)
        assert_eq!(core::mem::size_of::<ExecqCandRaw>(), 48 + 552);
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

    /// Lot 318 (the review of #538): of the three filesystem types with
    /// `FUSE_SUPER_MAGIC`, `virtiofs` alone is told apart — by the whole
    /// name, its NUL included, as the kernel half reads it.
    #[test]
    fn virtiofs_is_told_from_a_user_s_fuse_by_its_type_name() {
        let words = |name: &[u8]| {
            let mut b = [0u8; 16];
            b[..name.len()].copy_from_slice(name);
            (
                u64::from_le_bytes(b[..8].try_into().unwrap()),
                u64::from_le_bytes(b[8..].try_into().unwrap()),
            )
        };
        let (a, b) = words(b"virtiofs");
        assert!(is_virtiofs_name(a, b));
        for other in [
            &b"fuse"[..],
            b"fuseblk",
            b"virtiofs2",
            b"virtio",
            b"",
            b"fuse.sshfs",
        ] {
            let (a, b) = words(other);
            assert!(
                !is_virtiofs_name(a, b),
                "{}",
                String::from_utf8_lossy(other)
            );
        }
    }
}
