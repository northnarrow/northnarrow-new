//! Exploit post-condition guard (EPG, lab PR 219) — the decision model the
//! eBPF programs run and the agent tests.
//!
//! Whatever bug a local kernel exploit uses, its goal is a post-condition:
//! an unprivileged task becomes root, gains capabilities, or leaves its user
//! namespace, its namespaces or its filesystem root. The kernel makes each
//! of those changes legitimately through one mechanism (`commit_creds`,
//! `switch_task_namespaces`, `set_fs_root`) and only on behalf of a few
//! system calls. The guard compares a task's privileges around every system
//! call (`raw_syscalls/sys_enter` and `sys_exit`) and, at the mechanism
//! hooks, the system call they run for. A gain that came through no
//! mechanism, or through a mechanism on behalf of a system call that never
//! makes that change, is the signature (design note
//! `docs/design/EXPLOIT_POSTCONDITION_GUARD.md`).
//!
//! The allow-list is about mechanisms, not names: no comm, path or uid is
//! exempt. A task already fully privileged (real uid 0 with every
//! capability in effect) is skipped: it has nothing left to gain.
//!
//! Everything here is `no_std`, loop-free on the paths the eBPF programs
//! use, and `#[inline(always)]` so the verifier sees straight-line code.
//! System call numbers are x86_64's (the only architecture the agent ships
//! for, capability C04); a 32-bit (`int 0x80`, `TS_COMPAT`) or x32 call is
//! judged on its own table.

/// x86_64 system call numbers the guard knows (`syscall_64.tbl`).
pub mod nr {
    pub const READ: u32 = 0;
    pub const WRITE: u32 = 1;
    pub const IOCTL: u32 = 16;
    pub const SETSOCKOPT: u32 = 54;
    pub const CLONE: u32 = 56;
    pub const FORK: u32 = 57;
    pub const VFORK: u32 = 58;
    pub const EXECVE: u32 = 59;
    pub const SETUID: u32 = 105;
    pub const SETGID: u32 = 106;
    pub const GETPPID: u32 = 110;
    pub const SETREUID: u32 = 113;
    pub const SETREGID: u32 = 114;
    pub const SETGROUPS: u32 = 116;
    pub const SETRESUID: u32 = 117;
    pub const SETRESGID: u32 = 119;
    pub const SETFSUID: u32 = 122;
    pub const SETFSGID: u32 = 123;
    pub const CAPSET: u32 = 126;
    pub const PIVOT_ROOT: u32 = 155;
    pub const PRCTL: u32 = 157;
    pub const CHROOT: u32 = 161;
    pub const KEYCTL: u32 = 250;
    pub const UNSHARE: u32 = 272;
    pub const SETNS: u32 = 308;
    pub const BPF: u32 = 321;
    pub const EXECVEAT: u32 = 322;
    pub const IO_URING_ENTER: u32 = 426;
    pub const CLONE3: u32 = 435;
}

/// i386 system call numbers (`syscall_32.tbl`), for a call made through
/// `int 0x80` / `sysenter` (`TS_COMPAT` set during the call).
pub mod nr32 {
    pub const FORK: u32 = 2;
    pub const EXECVE: u32 = 11;
    pub const SETUID16: u32 = 23;
    pub const SETGID16: u32 = 46;
    pub const IOCTL: u32 = 54;
    pub const CHROOT: u32 = 61;
    pub const SETREUID16: u32 = 70;
    pub const SETREGID16: u32 = 71;
    pub const SETGROUPS16: u32 = 81;
    pub const CLONE: u32 = 120;
    pub const SETFSUID16: u32 = 138;
    pub const SETFSGID16: u32 = 139;
    pub const SETRESUID16: u32 = 164;
    pub const SETRESGID16: u32 = 170;
    pub const PRCTL: u32 = 172;
    pub const CAPSET: u32 = 185;
    pub const VFORK: u32 = 190;
    pub const SETREUID: u32 = 203;
    pub const SETREGID: u32 = 204;
    pub const SETGROUPS: u32 = 206;
    pub const SETRESUID: u32 = 208;
    pub const SETRESGID: u32 = 210;
    pub const SETUID: u32 = 213;
    pub const SETGID: u32 = 214;
    pub const SETFSUID: u32 = 215;
    pub const SETFSGID: u32 = 216;
    pub const PIVOT_ROOT: u32 = 217;
    pub const UNSHARE: u32 = 310;
    pub const SETNS: u32 = 346;
    pub const EXECVEAT: u32 = 358;
    pub const CLONE3: u32 = 435;
}

/// `__X32_SYSCALL_BIT`: set in the number of an x32-ABI call.
pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;
/// x32's own `execve` / `execveat` numbers (the rest are the x86_64 ones).
pub const X32_EXECVE: u32 = 520;
pub const X32_EXECVEAT: u32 = 545;
/// x86 `thread_info.status` bit set while a 32-bit call runs (cleared on the
/// way back to user mode, after the `sys_exit` tracepoint).
pub const TS_COMPAT: u32 = 0x0002;
/// `raw_syscalls/sys_enter` id of a call the kernel does not run (-1).
pub const NO_SYSCALL: u32 = u32::MAX;

/// The system call ABI a number belongs to.
pub mod abi {
    pub const X64: u8 = 0;
    pub const IA32: u8 = 1;
    pub const X32: u8 = 2;
    /// No system call (a mechanism outside any call: task work, an interrupt).
    pub const NONE: u8 = 3;
}

/// The ABI of a call and its number in that ABI's table.
#[inline(always)]
pub const fn split_abi(raw_nr: u32, compat: bool) -> (u8, u32) {
    if compat {
        (abi::IA32, raw_nr)
    } else if raw_nr != NO_SYSCALL && raw_nr & X32_SYSCALL_BIT != 0 {
        (abi::X32, raw_nr & !X32_SYSCALL_BIT)
    } else {
        (abi::X64, raw_nr)
    }
}

/// What a system call changed, as a bit set.
pub mod change {
    /// A uid or gid the task did not hold (real, effective, saved, fs).
    pub const IDS: u32 = 1 << 0;
    /// A capability outside the task's permitted set.
    pub const CAPS: u32 = 1 << 1;
    /// Another user namespace.
    pub const USERNS: u32 = 1 << 2;
    /// Another `nsproxy` (mount, pid, network, uts, ipc, cgroup, time).
    pub const NSPROXY: u32 = 1 << 3;
    /// Another filesystem root (`fs->root`).
    pub const ROOT: u32 = 1 << 4;
    /// Another `fs_struct` (`task->fs` replaced).
    pub const FS: u32 = 1 << 5;
    /// The credential changes, together.
    pub const CRED: u32 = IDS | CAPS | USERNS;
}

/// The kernel mechanisms the guard hooks, as seen during the current call.
pub mod mech {
    pub const COMMIT_CREDS: u32 = 1 << 0;
    pub const SWITCH_NS: u32 = 1 << 1;
    pub const SET_FS_ROOT: u32 = 1 << 2;
    pub const ALL: u32 = COMMIT_CREDS | SWITCH_NS | SET_FS_ROOT;
}

/// The mechanism through which the kernel makes a change legitimately.
#[inline(always)]
pub const fn mechanism_for(change_bit: u32) -> u32 {
    match change_bit {
        change::IDS | change::CAPS | change::USERNS => mech::COMMIT_CREDS,
        change::NSPROXY => mech::SWITCH_NS,
        change::ROOT => mech::SET_FS_ROOT,
        // `unshare(CLONE_FS)` assigns `current->fs` itself.
        _ => 0,
    }
}

/// The allowed-transition table: the changes a system call may make to its
/// caller, `0` for every call not listed. Through a mechanism only
/// ([`mechanism_for`]), except a `pivot_root` root (`chroot_fs_refs`) and an
/// `unshare(CLONE_FS)` `fs_struct`.
///
/// `clone`, `clone3`, `fork` and `vfork` are listed with nothing: the new
/// namespaces and credentials are the child's, which starts with no
/// snapshot. `setgroups` changes the supplementary groups, which the guard
/// does not compare, and `prctl` the ambient set and the securebits, which
/// grant no permitted or effective capability: a gain inside either is an
/// anomaly.
#[inline(always)]
pub const fn allowed(abi_: u8, nr_: u32) -> u32 {
    match abi_ {
        abi::X64 => allowed_x64(nr_),
        abi::IA32 => allowed_ia32(nr_),
        abi::X32 => match nr_ {
            X32_EXECVE | X32_EXECVEAT => change::IDS | change::CAPS,
            // x32 shares x86_64's numbers for everything else listed (no
            // recursion: the eBPF verifier refuses recursive calls).
            _ => allowed_x64(nr_),
        },
        _ => 0,
    }
}

#[inline(always)]
const fn allowed_x64(nr_: u32) -> u32 {
    use change::*;
    match nr_ {
        nr::SETUID
        | nr::SETGID
        | nr::SETREUID
        | nr::SETREGID
        | nr::SETRESUID
        | nr::SETRESGID
        | nr::SETFSUID
        | nr::SETFSGID
        | nr::SETGROUPS => IDS,
        nr::CAPSET => CAPS,
        nr::EXECVE | nr::EXECVEAT => IDS | CAPS,
        nr::UNSHARE => CAPS | USERNS | NSPROXY | FS | ROOT,
        nr::SETNS => CAPS | USERNS | NSPROXY | ROOT,
        nr::CHROOT | nr::PIVOT_ROOT => ROOT,
        _ => 0,
    }
}

#[inline(always)]
const fn allowed_ia32(nr_: u32) -> u32 {
    use change::*;
    match nr_ {
        nr32::SETUID16
        | nr32::SETGID16
        | nr32::SETREUID16
        | nr32::SETREGID16
        | nr32::SETGROUPS16
        | nr32::SETFSUID16
        | nr32::SETFSGID16
        | nr32::SETRESUID16
        | nr32::SETRESGID16
        | nr32::SETREUID
        | nr32::SETREGID
        | nr32::SETGROUPS
        | nr32::SETRESUID
        | nr32::SETRESGID
        | nr32::SETUID
        | nr32::SETGID
        | nr32::SETFSUID
        | nr32::SETFSGID => IDS,
        nr32::CAPSET => CAPS,
        nr32::EXECVE | nr32::EXECVEAT => IDS | CAPS,
        nr32::UNSHARE => CAPS | USERNS | NSPROXY | FS | ROOT,
        nr32::SETNS => CAPS | USERNS | NSPROXY | ROOT,
        nr32::CHROOT | nr32::PIVOT_ROOT => ROOT,
        _ => 0,
    }
}

/// Numbers below this have an entry in [`ALLOWED_TABLE`]: every call
/// [`allowed`] lists is below it (`X32_EXECVEAT`, 545, is the highest).
pub const ALLOWED_NRS: usize = 1024;

/// [`allowed`] as a table, entry `abi * ALLOWED_NRS + nr` (rows x86-64,
/// ia32, x32, and [`abi::NONE`]'s, all zeroes), built at compile time from
/// [`allowed`] itself. The eBPF programs judge through it
/// ([`allowed_in_table`]): the `match` above compiles to a chain of
/// comparisons on the call number, and each one splits the verifier's paths
/// with the number a known constant on each side — fifty ways through every
/// verdict, which the 5.15 and 6.1 verifiers do not merge again (lab PR 219:
/// the exploit guard's programs ran into the 1M-instruction limit there;
/// KERNEL_COMPATIBILITY "Older verifiers", rule 10). One load from a
/// read-only table is one unknown value.
pub const ALLOWED_TABLE: [u8; 4 * ALLOWED_NRS] = allowed_table();

const fn allowed_table() -> [u8; 4 * ALLOWED_NRS] {
    let mut t = [0u8; 4 * ALLOWED_NRS];
    let mut a = 0;
    while a < 4 {
        let mut n = 0;
        while n < ALLOWED_NRS {
            t[a * ALLOWED_NRS + n] = allowed(a as u8, n as u32) as u8;
            n += 1;
        }
        a += 1;
    }
    t
}

/// [`allowed`], read from [`ALLOWED_TABLE`]: the same answer for every ABI
/// and number (one past the table is listed nowhere). Branch-free: the
/// masks keep the index inside the table whatever the verifier knows of
/// the operands (a bound checked on one copy of a value is not one it
/// knows on another), and the range test only zeroes the answer.
#[inline(always)]
pub const fn allowed_in_table(abi_: u8, nr_: u32) -> u32 {
    let row = (abi_ as usize) & 3;
    let col = (nr_ as usize) & (ALLOWED_NRS - 1);
    let v = ALLOWED_TABLE[row * ALLOWED_NRS + col] as u32;
    let in_range = ((abi_ as usize) < 4) as u32 & ((nr_ as usize) < ALLOWED_NRS) as u32;
    v & in_range.wrapping_neg()
}

/// `true` for the calls whose own effect is a new root with no mechanism
/// (`pivot_root` replaces the roots through `chroot_fs_refs`).
#[inline(always)]
pub const fn is_pivot_root(abi_: u8, nr_: u32) -> bool {
    ((abi_ == abi::X64 || abi_ == abi::X32) && nr_ == nr::PIVOT_ROOT)
        || (abi_ == abi::IA32 && nr_ == nr32::PIVOT_ROOT)
}

/// What the guard compares of a credential. Kernel ids (`kuid_t`/`kgid_t`),
/// so uid 0 inside a user namespace is the host uid it maps to.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Identity {
    /// `cred.uid, gid, suid, sgid, euid, egid, fsuid, fsgid`, in the
    /// kernel's order (one read of 32 bytes).
    pub ids: [u32; 8],
    /// `cred.cap_permitted` (a 64-bit set on every supported kernel).
    pub cap_permitted: u64,
    /// `cred.cap_effective`.
    pub cap_effective: u64,
    /// `cred.user_ns` (its address: the guard compares identity, not
    /// content).
    pub user_ns: u64,
}

/// Positions in [`Identity::ids`].
pub mod id {
    pub const UID: usize = 0;
    pub const GID: usize = 1;
    pub const SUID: usize = 2;
    pub const SGID: usize = 3;
    pub const EUID: usize = 4;
    pub const EGID: usize = 5;
    pub const FSUID: usize = 6;
    pub const FSGID: usize = 7;
}

#[inline(always)]
const fn held(ids: &[u32; 8], first: usize, v: u32) -> bool {
    // uid family at 0, 2, 4, 6; gid family at 1, 3, 5, 7.
    v == ids[first] || v == ids[first + 2] || v == ids[first + 4] || v == ids[first + 6]
}

#[inline(always)]
const fn family_gains(before: &[u32; 8], after: &[u32; 8], first: usize) -> bool {
    !held(before, first, after[first])
        || !held(before, first, after[first + 2])
        || !held(before, first, after[first + 4])
        || !held(before, first, after[first + 6])
}

/// What `after` holds that `before` did not, as [`change`] bits: a uid or
/// gid that was none of the task's four (becoming another user, root
/// included, is something only the setuid calls and exec do; returning to
/// an id the task held is not a change), a capability outside its permitted
/// set (an effective bit restored from permitted is not a gain), another
/// user namespace. Losing capabilities is never a change.
#[inline(always)]
pub const fn cred_gain(before: &Identity, after: &Identity) -> u32 {
    let mut g = 0;
    if family_gains(&before.ids, &after.ids, id::UID)
        || family_gains(&before.ids, &after.ids, id::GID)
    {
        g |= change::IDS;
    }
    if (after.cap_permitted | after.cap_effective) & !before.cap_permitted != 0 {
        g |= change::CAPS;
    }
    if after.user_ns != before.user_ns {
        g |= change::USERNS;
    }
    g
}

/// Every capability up to `cap_last_cap` (from
/// `/proc/sys/kernel/cap_last_cap`).
#[inline(always)]
pub const fn full_cap_mask(cap_last_cap: u32) -> u64 {
    if cap_last_cap >= 63 {
        u64::MAX
    } else {
        (1u64 << (cap_last_cap + 1)) - 1
    }
}

/// A task with nothing left to gain: host real uid 0 and every capability
/// in effect. Skipped at `sys_enter` (no snapshot), so its own transitions
/// are not judged.
#[inline(always)]
pub const fn fully_privileged(host_ruid: u32, cap_effective: u64, full_mask: u64) -> bool {
    host_ruid == 0 && cap_effective & full_mask == full_mask
}

/// Anomaly kinds (the `kind` byte of the wire record).
pub mod kind {
    /// Credentials gained with no `commit_creds` during the call: a write
    /// into the task's `struct cred`, or its pointer replaced.
    pub const CRED_NO_MECHANISM: u8 = 1;
    /// `commit_creds` gave privileges on behalf of a call that never does
    /// (the `commit_creds(prepare_kernel_cred(…))` of a kernel ROP chain).
    pub const CRED_FROM_SYSCALL: u8 = 2;
    /// Another `nsproxy` with no `switch_task_namespaces`.
    pub const NS_NO_MECHANISM: u8 = 3;
    /// `switch_task_namespaces` on behalf of a call that never switches.
    pub const NS_FROM_SYSCALL: u8 = 4;
    /// Another filesystem root with no `set_fs_root`, no `pivot_root`, and
    /// no root change anywhere on the host since the previous call.
    pub const ROOT_NO_MECHANISM: u8 = 5;
    /// `set_fs_root` on behalf of a call that never sets a root.
    pub const ROOT_FROM_SYSCALL: u8 = 6;
    /// `task->fs` replaced outside `unshare`.
    pub const FS_SWAPPED: u8 = 7;
    /// Credentials gained while the task was in user mode, or in a call
    /// whose exit the kernel never ran (an exploit's return gadget).
    pub const CRED_BETWEEN_SYSCALLS: u8 = 8;
    /// `commit_creds` gave privileges outside any call of a task that was
    /// not fully privileged (task work, interrupt context).
    pub const CRED_OUTSIDE_SYSCALL: u8 = 9;
    pub const MAX: u8 = 9;
}

/// `true` for the kinds about credentials (ATT&CK T1068); the others are
/// namespace and root kinds (T1611).
#[inline(always)]
pub const fn is_credential_kind(k: u8) -> bool {
    matches!(
        k,
        kind::CRED_NO_MECHANISM
            | kind::CRED_FROM_SYSCALL
            | kind::CRED_BETWEEN_SYSCALLS
            | kind::CRED_OUTSIDE_SYSCALL
    )
}

/// What the `sys_exit` program knows about one call.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExitObservation {
    /// The snapshot taken at `sys_enter`.
    pub before: Identity,
    /// The credential at `sys_exit`.
    pub after: Identity,
    /// The [`mech`] bits seen during the call.
    pub mechanisms: u32,
    /// [`abi`] and number of the call.
    pub abi: u8,
    pub nr: u32,
    /// `task->nsproxy` differs from the snapshot.
    pub nsproxy_changed: bool,
    /// `task->fs` differs from the snapshot.
    pub fs_changed: bool,
    /// `task->fs->root.dentry` differs from the snapshot.
    pub root_changed: bool,
    /// Some task on the host set a root (`set_fs_root`, `pivot_root`) since
    /// the snapshot: a shared `fs_struct` or a `pivot_root` in this mount
    /// namespace changes this task's root with no mechanism of its own.
    pub root_epoch_advanced: bool,
}

/// The `sys_exit` verdict: the first anomaly, credentials first.
#[inline(always)]
pub const fn judge_exit(o: &ExitObservation) -> Option<u8> {
    let allowed_here = allowed_in_table(o.abi, o.nr);
    let gain = cred_gain(&o.before, &o.after);
    if gain != 0 {
        if o.mechanisms & mech::COMMIT_CREDS == 0 {
            return Some(kind::CRED_NO_MECHANISM);
        }
        if allowed_here & gain != gain {
            return Some(kind::CRED_FROM_SYSCALL);
        }
    }
    if o.nsproxy_changed {
        if o.mechanisms & mech::SWITCH_NS == 0 {
            return Some(kind::NS_NO_MECHANISM);
        }
        if allowed_here & change::NSPROXY == 0 {
            return Some(kind::NS_FROM_SYSCALL);
        }
    }
    if o.fs_changed {
        if allowed_here & change::FS == 0 {
            return Some(kind::FS_SWAPPED);
        }
    } else if o.root_changed {
        if o.mechanisms & mech::SET_FS_ROOT != 0 {
            if allowed_here & change::ROOT == 0 {
                return Some(kind::ROOT_FROM_SYSCALL);
            }
        } else if !is_pivot_root(o.abi, o.nr) && !o.root_epoch_advanced {
            return Some(kind::ROOT_NO_MECHANISM);
        }
    }
    None
}

/// The `commit_creds` verdict, from the call's snapshot and the new
/// credential. `in_syscall` is `false` for a commit outside a judged call;
/// the caller has already skipped a fully privileged task.
#[inline(always)]
pub const fn judge_commit(gain: u32, abi_: u8, nr_: u32, in_syscall: bool) -> Option<u8> {
    if gain == 0 {
        return None;
    }
    if !in_syscall {
        return Some(kind::CRED_OUTSIDE_SYSCALL);
    }
    if allowed_in_table(abi_, nr_) & gain != gain {
        return Some(kind::CRED_FROM_SYSCALL);
    }
    None
}

/// The `switch_task_namespaces(current, new)` verdict.
#[inline(always)]
pub const fn judge_switch_ns(abi_: u8, nr_: u32, in_syscall: bool) -> Option<u8> {
    if !in_syscall || allowed_in_table(abi_, nr_) & change::NSPROXY == 0 {
        return Some(kind::NS_FROM_SYSCALL);
    }
    None
}

/// The `set_fs_root(current->fs, …)` verdict.
#[inline(always)]
pub const fn judge_set_fs_root(abi_: u8, nr_: u32, in_syscall: bool) -> Option<u8> {
    if !in_syscall || allowed_in_table(abi_, nr_) & change::ROOT == 0 {
        return Some(kind::ROOT_FROM_SYSCALL);
    }
    None
}

/// The `sys_enter` verdict: a gain since the previous judged exit.
#[inline(always)]
pub const fn judge_enter(last: &Identity, now: &Identity) -> Option<u8> {
    if cred_gain(last, now) != 0 {
        Some(kind::CRED_BETWEEN_SYSCALLS)
    } else {
        None
    }
}

/// Response the kernel took (the `action` byte of the wire record).
pub mod action {
    /// Detect mode: recorded, the task continues.
    pub const RECORDED: u8 = 0;
    /// Enforce mode: `SIGKILL` sent before the task returns to user mode.
    pub const KILLED: u8 = 1;
    /// Enforce mode, but the signal could not be sent.
    pub const KILL_FAILED: u8 = 2;
}

/// Guard modes (`GuardConfig::mode`).
pub mod cfg {
    /// Detect: record, the task continues. Also the value of an unwritten
    /// map.
    pub const MODE_DETECT: u32 = 0;
    /// Enforce: `SIGKILL` at the hook, then record (lite's use points also
    /// refuse the use, `-EPERM`).
    pub const MODE_ENFORCE: u32 = 1;
}

/// Which guard runs (`GuardConfig::variant`, the record's `variant`).
pub mod variant {
    /// Default: no system-call hooks. The mechanism hooks judge the call in
    /// progress (`orig_ax`); the use points (`capable`, exec, a filtered
    /// `file_open`) compare the task's objective credential and `nsproxy`
    /// with the last ones the kernel's mechanisms gave it.
    pub const LITE: u8 = 1;
    /// Opt-in: the `sys_enter` / `sys_exit` comparison around every call.
    pub const STRICT: u8 = 2;
}

/// Where an anomaly was caught (the record's `point`).
pub mod point {
    pub const SYS_ENTER: u8 = 1;
    pub const SYS_EXIT: u8 = 2;
    pub const COMMIT_CREDS: u8 = 3;
    pub const SWITCH_NS: u8 = 4;
    pub const SET_FS_ROOT: u8 = 5;
    /// LSM `capable` (every capability check of the task).
    pub const CAPABLE: u8 = 6;
    /// LSM `bprm_check_security`.
    pub const EXEC: u8 = 7;
    /// LSM `file_open` of a file [`super::file_open_is_guarded`].
    pub const FILE_OPEN: u8 = 8;
    /// `true` for the lite use points (where enforce also refuses the use).
    pub const fn is_use_point(p: u8) -> bool {
        matches!(p, CAPABLE | EXEC | FILE_OPEN)
    }
}

/// Byte offset of `orig_ax` in x86_64's `struct pt_regs` (uapi: r15, r14,
/// r13, r12, bp, bx, r11, r10, r9, r8, ax, cx, dx, si, di, orig_ax).
pub const PT_REGS_ORIG_AX: u32 = 120;

/// The call a task is in, from its `pt_regs.orig_ax` (`bpf_task_pt_regs`)
/// and `TS_COMPAT`: `None` when it is in none (a negative `orig_ax`: an
/// interrupt or an exception entry).
#[inline(always)]
pub const fn syscall_of(orig_ax: u64, compat: bool) -> Option<(u8, u32)> {
    if (orig_ax as i64) < 0 {
        None
    } else {
        Some(split_abi(orig_ax as u32, compat))
    }
}

/// The lite `file_open` filter: a file owned by uid 0 that is not
/// world-readable (`/etc/shadow`, `/root/...`, keys). Any other open costs
/// two reads and no lookup.
#[inline(always)]
pub const fn file_open_is_guarded(owner_uid: u32, mode: u16) -> bool {
    owner_uid == 0 && mode & 0o004 == 0
}

/// The lite use-point verdict: the task's objective credential now against
/// the one the kernel last committed (or the task started with), and its
/// `nsproxy` against the last one switched to. Every legitimate change goes
/// through a mechanism the guard records, so any gain here — and any other
/// `nsproxy` — was made without one.
#[inline(always)]
pub const fn judge_use(
    committed: &Identity,
    now: &Identity,
    committed_ns: u64,
    now_ns: u64,
) -> Option<u8> {
    if cred_gain(committed, now) != 0 {
        Some(kind::CRED_NO_MECHANISM)
    } else if committed_ns != 0 && now_ns != committed_ns {
        Some(kind::NS_NO_MECHANISM)
    } else {
        None
    }
}

/// A task whose last committed credential is fully privileged has nothing
/// to gain: lite skips its use points without reading anything.
#[inline(always)]
pub const fn lite_skips(committed: &Identity, full_mask: u64) -> bool {
    fully_privileged(committed.ids[id::UID], committed.cap_effective, full_mask)
}

/// The guard's whole configuration, the one entry of `EPG_CONFIG`: one map
/// lookup per program run instead of one per offset, and offsets only from
/// the agent, which resolved them from the running kernel's BTF and checked
/// the layout the programs assume. `armed` stays 0 until every program is
/// attached; the programs do nothing until then.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GuardConfig {
    pub armed: u32,
    /// [`cfg::MODE_DETECT`] or [`cfg::MODE_ENFORCE`].
    pub mode: u32,
    /// [`full_cap_mask`] of the running kernel.
    pub full_cap_mask: u64,
    /// `task_struct.cred`, `.nsproxy`, `.fs`, `.thread_info.status`.
    pub task_cred: u32,
    pub task_nsproxy: u32,
    pub task_fs: u32,
    pub task_ti_status: u32,
    /// `fs_struct.root` + `path.dentry`.
    pub fs_root_dentry: u32,
    /// `cred.uid` (8 ids follow), `cred.cap_permitted` (`cap_effective`
    /// follows), `cred.user_ns`.
    pub cred_uid: u32,
    pub cred_caps: u32,
    pub cred_user_ns: u32,
    /// `nsproxy.mnt_ns`, `.pid_ns_for_children`, `.net_ns`.
    pub nsproxy_mnt: u32,
    pub nsproxy_pid: u32,
    pub nsproxy_net: u32,
    /// `ns.inum` in `mnt_namespace`, `pid_namespace`, `net`,
    /// `user_namespace`.
    pub mnt_inum: u32,
    pub pid_inum: u32,
    pub net_inum: u32,
    pub user_inum: u32,
    /// [`variant::LITE`] or [`variant::STRICT`].
    pub variant: u32,
    /// Lab fault injection (`debug-trigger` builds only, `NN_EPG_INJECT_COMM`):
    /// the comm, packed little-endian ([`pack_comm`]), of a process whose
    /// `getppid` exit (strict) or first use point (lite: `capable`, exec)
    /// the guard reports as an anomaly marked injected — nothing changes,
    /// nobody gains anything; the record, the rule, the posture and the
    /// enforce-mode response are exercised. 0 (every build unless the lab
    /// sets it): off.
    pub inject_comm_lo: u64,
    pub inject_comm_hi: u64,
    /// Lite: `task_struct.real_cred`, `file.f_inode`, `inode.i_mode`,
    /// `inode.i_uid`.
    pub task_real_cred: u32,
    pub file_inode: u32,
    pub inode_mode: u32,
    pub inode_uid: u32,
    /// Lite: `task_struct.start_time` (`CLOCK_MONOTONIC` ns at fork), which
    /// tells a task's record from one an earlier task left at the same
    /// address ([`lite_entry`]); `task_struct.flags` (the threads no fork
    /// tracepoint sees, [`baseline_lost`]).
    pub task_start_time: u32,
    pub task_flags: u32,
    /// Lite: `CLOCK_MONOTONIC` when the guard was armed, written by the
    /// agent just after arming (0 until then). A task started at or after
    /// it had its baseline taken at fork, so finding none later means the
    /// task map lost it ([`baseline_lost`]).
    pub armed_at_ns: u64,
}

/// A 16-byte comm as two little-endian words (compared without `memcmp`
/// in the eBPF program).
#[inline(always)]
pub const fn pack_comm(c: &[u8; 16]) -> (u64, u64) {
    let mut lo = 0u64;
    let mut hi = 0u64;
    let mut i = 0;
    while i < 8 {
        lo |= (c[i] as u64) << (8 * i);
        hi |= (c[i + 8] as u64) << (8 * i);
        i += 1;
    }
    (lo, hi)
}

/// The kernel layout the agent resolved, before [`guard_config`] checks it.
#[derive(Clone, Copy, Debug, Default)]
pub struct ResolvedLayout {
    pub task_cred: Option<u32>,
    pub task_nsproxy: Option<u32>,
    pub task_fs: Option<u32>,
    pub task_ti_status: Option<u32>,
    pub fs_root: Option<u32>,
    pub path_dentry: Option<u32>,
    pub cred_uid: Option<u32>,
    pub cred_fsgid: Option<u32>,
    pub cred_cap_permitted: Option<u32>,
    pub cred_cap_effective: Option<u32>,
    pub cred_user_ns: Option<u32>,
    pub nsproxy_mnt: Option<u32>,
    pub nsproxy_pid: Option<u32>,
    pub nsproxy_net: Option<u32>,
    pub mnt_inum: Option<u32>,
    pub pid_inum: Option<u32>,
    pub net_inum: Option<u32>,
    pub user_inum: Option<u32>,
    pub task_real_cred: Option<u32>,
    pub file_inode: Option<u32>,
    pub inode_mode: Option<u32>,
    pub inode_uid: Option<u32>,
    pub task_start_time: Option<u32>,
    pub task_flags: Option<u32>,
}

/// The configuration for `layout`, unarmed, or the first reason the guard
/// cannot run on this kernel: a field missing, or a layout the programs
/// would misread (the eight ids read as one block, the two capability sets
/// as another).
pub fn guard_config(
    l: &ResolvedLayout,
    cap_last_cap: u32,
    mode: u32,
    variant_: u8,
) -> Result<GuardConfig, &'static str> {
    const LIMIT: u32 = 0xffff;
    macro_rules! need {
        ($f:ident, $why:literal) => {
            match l.$f {
                Some(v) if v < LIMIT => v,
                _ => return Err($why),
            }
        };
    }
    let task_cred = need!(task_cred, "task_struct.cred not resolved");
    let task_nsproxy = need!(task_nsproxy, "task_struct.nsproxy not resolved");
    let task_fs = need!(task_fs, "task_struct.fs not resolved");
    let task_ti_status = need!(
        task_ti_status,
        "task_struct.thread_info.status not resolved"
    );
    let fs_root = need!(fs_root, "fs_struct.root not resolved");
    let path_dentry = need!(path_dentry, "path.dentry not resolved");
    let cred_uid = need!(cred_uid, "cred.uid not resolved");
    let cred_fsgid = need!(cred_fsgid, "cred.fsgid not resolved");
    let cred_caps = need!(cred_cap_permitted, "cred.cap_permitted not resolved");
    let cred_eff = need!(cred_cap_effective, "cred.cap_effective not resolved");
    let cred_user_ns = need!(cred_user_ns, "cred.user_ns not resolved");
    let nsproxy_mnt = need!(nsproxy_mnt, "nsproxy.mnt_ns not resolved");
    let nsproxy_pid = need!(nsproxy_pid, "nsproxy.pid_ns_for_children not resolved");
    let nsproxy_net = need!(nsproxy_net, "nsproxy.net_ns not resolved");
    let mnt_inum = need!(mnt_inum, "mnt_namespace.ns.inum not resolved");
    let pid_inum = need!(pid_inum, "pid_namespace.ns.inum not resolved");
    let net_inum = need!(net_inum, "net.ns.inum not resolved");
    let user_inum = need!(user_inum, "user_namespace.ns.inum not resolved");
    if cred_fsgid != cred_uid + 28 {
        return Err("cred ids are not eight consecutive 32-bit fields (fsgid != uid + 28)");
    }
    if cred_eff != cred_caps + 8 {
        return Err("cred.cap_effective does not follow cred.cap_permitted");
    }
    if mode != cfg::MODE_DETECT && mode != cfg::MODE_ENFORCE {
        return Err("unknown guard mode");
    }
    let (task_real_cred, file_inode, inode_mode, inode_uid, task_start_time, task_flags) =
        match variant_ {
            variant::LITE => (
                need!(task_real_cred, "task_struct.real_cred not resolved"),
                need!(file_inode, "file.f_inode not resolved"),
                need!(inode_mode, "inode.i_mode not resolved"),
                need!(inode_uid, "inode.i_uid not resolved"),
                need!(task_start_time, "task_struct.start_time not resolved"),
                need!(task_flags, "task_struct.flags not resolved"),
            ),
            variant::STRICT => (0, 0, 0, 0, 0, 0),
            _ => return Err("unknown guard variant"),
        };
    Ok(GuardConfig {
        armed: 0,
        mode,
        full_cap_mask: full_cap_mask(cap_last_cap),
        task_cred,
        task_nsproxy,
        task_fs,
        task_ti_status,
        fs_root_dentry: fs_root + path_dentry,
        cred_uid,
        cred_caps,
        cred_user_ns,
        nsproxy_mnt,
        nsproxy_pid,
        nsproxy_net,
        mnt_inum,
        pid_inum,
        net_inum,
        user_inum,
        variant: variant_ as u32,
        inject_comm_lo: 0,
        inject_comm_hi: 0,
        task_real_cred,
        file_inode,
        inode_mode,
        inode_uid,
        task_start_time,
        task_flags,
        armed_at_ns: 0,
    })
}

/// `EPG_COUNTERS` slots (per-CPU, summed by the agent).
pub mod counter {
    /// Calls judged at `sys_exit`.
    pub const CHECKED: u32 = 0;
    /// `sys_enter` of a fully privileged task (no snapshot).
    pub const SKIPPED_PRIVILEGED: u32 = 1;
    /// Tasks given a snapshot.
    pub const TRACKED: u32 = 2;
    /// Snapshots re-taken after a fully privileged task's own change.
    pub const REBASED: u32 = 3;
    /// `commit_creds` calls by tracked tasks.
    pub const COMMITS: u32 = 4;
    /// Anomalies found (recorded or not).
    pub const ANOMALIES: u32 = 5;
    /// Tasks sent `SIGKILL` (enforce).
    pub const KILLS: u32 = 6;
    /// Anomalies not put on the ring: the task's report budget was spent.
    pub const REPORTS_HELD: u32 = 7;
    /// `sys_enter` of a task whose previous call never reached `sys_exit`.
    pub const EXIT_BYPASSED: u32 = 8;
    /// A snapshot the task map refused (the call is not judged).
    pub const UNTRACKED: u32 = 9;
    /// Lite: use points judged (a fully privileged task's are not).
    pub const USE_CHECKS: u32 = 10;
    /// Lite enforce: uses refused (`-EPERM`).
    pub const DENIED: u32 = 11;
    /// Lite: tasks first seen at a hook that started before the guard was
    /// armed, or that no fork tracepoint sees (io_uring and vhost workers):
    /// snapshot taken there.
    pub const LAZY_BASELINES: u32 = 12;
    /// Lite: tasks started after arming whose record was gone at a hook —
    /// the LRU task map evicted it, or the fork-time insert failed. The
    /// snapshot is re-taken there and marked; one that holds privilege is
    /// recorded as degraded evidence (`wire::epg::flags::BASELINE_LOST`).
    /// The agent attests every increase.
    pub const BASELINES_LOST: u32 = 13;
    pub const SLOTS: u32 = 14;
    pub const NAMES: [&str; SLOTS as usize] = [
        "checked",
        "skipped_privileged",
        "tracked",
        "rebased",
        "commits",
        "anomalies",
        "kills",
        "reports_held",
        "exit_bypassed",
        "untracked",
        "use_checks",
        "denied",
        "lazy_baselines",
        "baselines_lost",
    ];
}

/// Ring records per task (the rest are counted in
/// [`counter::REPORTS_HELD`]).
pub const REPORTS_PER_TASK: u32 = 4;

/// Strict's task map: the compiled size, replaced at load by the agent
/// (`pid_max` unless `--exploit-guard-tasks`); not preallocated, so it costs
/// only the live entries (which needs 6.1+: older kernels load a
/// non-preallocated map in a raw tracepoint with a WARN, so the agent
/// refuses strict there — `sensors::epg::strict_unsupported`).
pub const TASKS_MAX: u32 = 32768;

/// Lite's task map (`EPG_LITE_TASKS`, `BPF_MAP_TYPE_LRU_HASH` keyed by the
/// `task_struct` address): the compiled size, which only a loader that does
/// not size it gets. An LRU map is always preallocated (about 150 bytes an
/// entry), so the agent sizes it at load: [`LITE_TASKS_DEFAULT`] at most
/// unless `--exploit-guard-tasks` says otherwise, and one entry when lite
/// is not the variant that runs.
pub const LITE_TASKS_COMPILED: u32 = 1024;
/// Lite's default size bound: `min(pid_max, threads-max)` (no more tasks
/// can be alive at once, so on most hosts the map cannot fill with live
/// tasks) capped here, about 10 MiB.
pub const LITE_TASKS_DEFAULT: u32 = 65536;
/// The largest lite map `--exploit-guard-tasks` may ask for (about
/// 150 MiB preallocated).
pub const LITE_TASKS_LIMIT: u32 = 1 << 20;

// The sizes nest, and the record's flags are distinct bits.
const _: () = {
    assert!(LITE_TASKS_COMPILED <= LITE_TASKS_DEFAULT);
    assert!(LITE_TASKS_DEFAULT <= LITE_TASKS_LIMIT);
    assert!(
        lite_flags::REBASELINED & (lite_flags::VALID | lite_flags::TAINTED | lite_flags::INJECTED)
            == 0
    );
};

/// Lite's per-task state (`EPG_LITE_TASKS` value, 88 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LiteState {
    /// The objective credential last committed (or the task's first).
    pub id: Identity,
    pub cred: u64,
    /// The `nsproxy` last switched to (or the task's first).
    pub nsproxy: u64,
    /// `task_struct.start_time` of the task this record is for
    /// ([`lite_entry`]).
    pub start_time: u64,
    /// [`lite_flags`].
    pub flags: u32,
    /// Ring records this task produced ([`REPORTS_PER_TASK`]).
    pub reports: u32,
}

/// `LiteState::flags`.
pub mod lite_flags {
    /// The snapshot is set.
    pub const VALID: u32 = 1 << 0;
    /// An anomaly was found: in enforce every later use is refused too.
    pub const TAINTED: u32 = 1 << 1;
    /// The lab injection fired once for this task.
    pub const INJECTED: u32 = 1 << 2;
    /// The snapshot was re-taken after the task's record was lost
    /// ([`super::baseline_lost`]): what it held then was not attributed to
    /// a mechanism. Later records of the task say so
    /// (`wire::epg::flags::REBASELINED`).
    pub const REBASELINED: u32 = 1 << 3;
}

/// What the lite record at a task's address says about the task there now
/// ([`lite_entry`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiteEntry {
    /// The record is this task's.
    Current,
    /// The task's start time went back: an exec by a non-leader thread,
    /// which takes its leader's pid and start time (`de_thread`) but keeps
    /// its own `task_struct`. The record is the task's; it follows the new
    /// start time.
    ThreadExec,
    /// An earlier task's (one that started before this one at the same
    /// address and left its record behind): not this task's.
    Stale,
}

/// The record started at `recorded_start` against the task at the same
/// address, started at `task_start`. A live task occupies its address from
/// its start, so a record with a later start time can only be its own from
/// before a `de_thread`, and one with an earlier start time is an earlier
/// task's.
#[inline(always)]
pub const fn lite_entry(recorded_start: u64, task_start: u64) -> LiteEntry {
    if recorded_start == task_start {
        LiteEntry::Current
    } else if recorded_start > task_start {
        LiteEntry::ThreadExec
    } else {
        LiteEntry::Stale
    }
}

/// `PF_IO_WORKER`: an io_uring worker (`create_io_thread`, no fork
/// tracepoint).
pub const PF_IO_WORKER: u32 = 0x0000_0010;
/// `PF_USER_WORKER` (6.4+; an unused bit before): a kernel-side worker
/// cloned from a user thread (io_uring, vhost), no fork tracepoint.
pub const PF_USER_WORKER: u32 = 0x0000_4000;

/// Lite: a task with no record at a hook should have had one. It started
/// at or after the guard was armed (`armed_at_ns`, 0 = not yet known), so
/// the armed fork program took its baseline, unless it is a worker no fork
/// tracepoint sees. Its record was lost: evicted from the LRU task map
/// (pressure, or a flood meant to evict it), or the fork-time insert
/// failed. A task that started earlier is merely first seen.
#[inline(always)]
pub const fn baseline_lost(task_start: u64, task_flags: u32, armed_at_ns: u64) -> bool {
    armed_at_ns != 0
        && task_start >= armed_at_ns
        && task_flags & (PF_IO_WORKER | PF_USER_WORKER) == 0
}

/// A credential that holds what a local exploit is after: uid or gid 0 in
/// any of the eight ids, or any capability permitted or in effect. Lite
/// records a snapshot re-taken after a lost baseline as degraded evidence
/// when it does: nothing can tell an in-place write from a legitimate
/// change made while the record was missing.
#[inline(always)]
pub const fn holds_privilege(i: &Identity) -> bool {
    let d = &i.ids;
    held(d, id::UID, 0) || held(d, id::GID, 0) || i.cap_permitted != 0 || i.cap_effective != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: u32 = 1000;
    const NS_HOST: u64 = 0xffff_0000_0000_1000;
    const NS_CHILD: u64 = 0xffff_0000_0000_2000;
    const FULL: u64 = (1 << 41) - 1; // cap_last_cap 40

    fn user() -> Identity {
        Identity {
            ids: [USER; 8],
            cap_permitted: 0,
            cap_effective: 0,
            user_ns: NS_HOST,
        }
    }

    fn root() -> Identity {
        Identity {
            ids: [0; 8],
            cap_permitted: FULL,
            cap_effective: FULL,
            user_ns: NS_HOST,
        }
    }

    /// A setuid-root program run by `USER` after exec: ruid stays the
    /// user's, euid/suid/fsuid 0, every capability permitted and in effect.
    fn setuid_root_image() -> Identity {
        let mut i = root();
        i.ids[id::UID] = USER;
        i.ids[id::GID] = USER;
        i.ids[id::SGID] = USER;
        i.ids[id::EGID] = USER;
        i.ids[id::FSGID] = USER;
        i
    }

    fn exit(
        abi_: u8,
        nr_: u32,
        before: Identity,
        after: Identity,
        mechanisms: u32,
    ) -> ExitObservation {
        ExitObservation {
            before,
            after,
            mechanisms,
            abi: abi_,
            nr: nr_,
            ..ExitObservation::default()
        }
    }

    #[test]
    fn full_cap_mask_covers_every_capability() {
        assert_eq!(full_cap_mask(40), FULL);
        assert_eq!(full_cap_mask(63), u64::MAX);
        assert_eq!(full_cap_mask(0), 1);
        assert!(fully_privileged(0, FULL, FULL));
        assert!(fully_privileged(0, u64::MAX, FULL));
        // root with a reduced bounding set (a rootful container, a hardened
        // unit) is still judged
        assert!(!fully_privileged(0, FULL & !(1 << 21), FULL));
        // a setuid-root image keeps the user's real uid
        assert!(!fully_privileged(USER, FULL, FULL));
    }

    #[test]
    fn gains_are_new_privileges_only() {
        assert_eq!(cred_gain(&user(), &user()), 0);
        assert_eq!(cred_gain(&user(), &root()), change::IDS | change::CAPS);
        // returning to an id the task held is no change; becoming another
        // user is (legitimate only through the setuid calls and exec)
        assert_eq!(cred_gain(&setuid_root_image(), &user()), 0);
        assert_eq!(cred_gain(&root(), &user()), change::IDS);
        // losing capabilities is never a change
        let mut capless = root();
        capless.cap_permitted = 0;
        capless.cap_effective = 0;
        assert_eq!(cred_gain(&root(), &capless), 0);
        // seteuid(0) in a setuid-root program that had dropped its euid: the
        // uid was the saved one and the effective set comes back from the
        // permitted set
        let mut dropped = setuid_root_image();
        dropped.ids[id::EUID] = USER;
        dropped.ids[id::FSUID] = USER;
        dropped.cap_effective = 0;
        assert_eq!(cred_gain(&dropped, &setuid_root_image()), 0);
        // a uid none of the four held is a gain, root or not
        let mut other = user();
        other.ids[id::FSUID] = 1001;
        assert_eq!(cred_gain(&user(), &other), change::IDS);
        let mut group0 = user();
        group0.ids[id::EGID] = 0;
        assert_eq!(cred_gain(&user(), &group0), change::IDS);
        // another user namespace
        let mut child = user();
        child.user_ns = NS_CHILD;
        child.cap_permitted = FULL;
        child.cap_effective = FULL;
        assert_eq!(cred_gain(&user(), &child), change::CAPS | change::USERNS);
        // leaving it for the host's is a gain too (the escape)
        let mut back = child;
        back.user_ns = NS_HOST;
        assert_eq!(cred_gain(&child, &back), change::USERNS);
    }

    /// The legitimate transitions of the negative suite pass at sys_exit.
    #[test]
    fn legitimate_transitions_pass() {
        let c = mech::COMMIT_CREDS;
        // sudo / su / passwd / newgrp: exec of a setuid program
        assert_eq!(
            judge_exit(&exit(abi::X64, nr::EXECVE, user(), setuid_root_image(), c)),
            None
        );
        assert_eq!(
            judge_exit(&exit(
                abi::X64,
                nr::EXECVEAT,
                user(),
                setuid_root_image(),
                c
            )),
            None
        );
        // then setresuid(0, 0, 0) and setgid / setgroups
        assert_eq!(
            judge_exit(&exit(
                abi::X64,
                nr::SETRESUID,
                setuid_root_image(),
                root(),
                c
            )),
            None
        );
        let mut g = setuid_root_image();
        g.ids[id::GID] = 0;
        assert_eq!(
            judge_exit(&exit(abi::X64, nr::SETGID, setuid_root_image(), g, c)),
            None
        );
        // capsh / setpriv: capset within the permitted set
        let mut perm = user();
        perm.cap_permitted = 1 << 12;
        let mut eff = perm;
        eff.cap_effective = 1 << 12;
        assert_eq!(judge_exit(&exit(abi::X64, nr::CAPSET, perm, eff, c)), None);
        // file capabilities at exec
        let mut fcap = user();
        fcap.cap_permitted = 1 << 13;
        fcap.cap_effective = 1 << 13;
        assert_eq!(
            judge_exit(&exit(abi::X64, nr::EXECVE, user(), fcap, c)),
            None
        );
        // unshare -U / -r: a new user namespace, every capability in it
        let mut child = user();
        child.user_ns = NS_CHILD;
        child.cap_permitted = FULL;
        child.cap_effective = FULL;
        assert_eq!(
            judge_exit(&exit(abi::X64, nr::UNSHARE, user(), child, c)),
            None
        );
        // setns into a user namespace (podman exec, nsenter -U)
        assert_eq!(
            judge_exit(&exit(abi::X64, nr::SETNS, user(), child, c)),
            None
        );
        // the same on the 32-bit table
        assert_eq!(
            judge_exit(&exit(
                abi::IA32,
                nr32::SETUID,
                setuid_root_image(),
                root(),
                c
            )),
            None
        );
        assert_eq!(
            judge_exit(&exit(
                abi::IA32,
                nr32::EXECVE,
                user(),
                setuid_root_image(),
                c
            )),
            None
        );
        assert_eq!(
            judge_exit(&exit(abi::X32, X32_EXECVE, user(), setuid_root_image(), c)),
            None
        );
        // a commit that changes nothing compared (keyctl join session,
        // landlock, seccomp, prctl keepcaps)
        assert_eq!(
            judge_exit(&exit(abi::X64, nr::KEYCTL, user(), user(), c)),
            None
        );
        assert_eq!(
            judge_exit(&exit(abi::X64, nr::PRCTL, user(), user(), c)),
            None
        );
        // dropping: a root task (reduced bounding set, so judged) becoming
        // the user, and capabilities lost in any call
        assert_eq!(
            judge_exit(&exit(abi::X64, nr::SETRESUID, root(), user(), c)),
            None
        );
        let mut capless = root();
        capless.cap_permitted = 0;
        capless.cap_effective = 0;
        assert_eq!(
            judge_exit(&exit(abi::X64, nr::PRCTL, root(), capless, c)),
            None
        );
    }

    #[test]
    fn credential_signatures() {
        // (a) an in-place write of uid/euid/fsuid from inside write(): no
        // commit_creds
        let mut flipped = user();
        flipped.ids[id::UID] = 0;
        flipped.ids[id::EUID] = 0;
        flipped.ids[id::FSUID] = 0;
        assert_eq!(
            judge_exit(&exit(abi::X64, nr::WRITE, user(), flipped, 0)),
            Some(kind::CRED_NO_MECHANISM)
        );
        // even during a call that may change ids: the mechanism is missing
        assert_eq!(
            judge_exit(&exit(abi::X64, nr::SETUID, user(), flipped, 0)),
            Some(kind::CRED_NO_MECHANISM)
        );
        // (b) commit_creds(prepare_kernel_cred(…)) from the usual entry
        // points of a kernel bug
        for n in [
            nr::IOCTL,
            nr::WRITE,
            nr::SETSOCKOPT,
            nr::KEYCTL,
            nr::BPF,
            nr::IO_URING_ENTER,
            nr::READ,
        ] {
            assert_eq!(
                judge_exit(&exit(abi::X64, n, user(), root(), mech::COMMIT_CREDS)),
                Some(kind::CRED_FROM_SYSCALL),
                "nr {n}"
            );
            assert_eq!(
                judge_commit(cred_gain(&user(), &root()), abi::X64, n, true),
                Some(kind::CRED_FROM_SYSCALL)
            );
        }
        // a prctl or setgroups that gains is outside the table
        assert_eq!(
            judge_exit(&exit(
                abi::X64,
                nr::PRCTL,
                user(),
                root(),
                mech::COMMIT_CREDS
            )),
            Some(kind::CRED_FROM_SYSCALL)
        );
        assert_eq!(
            judge_exit(&exit(
                abi::X64,
                nr::SETGROUPS,
                user(),
                root(),
                mech::COMMIT_CREDS
            )),
            Some(kind::CRED_FROM_SYSCALL)
        );
        // capset may raise effective within permitted, never permitted
        assert_eq!(
            judge_exit(&exit(
                abi::X64,
                nr::CAPSET,
                user(),
                root(),
                mech::COMMIT_CREDS
            )),
            Some(kind::CRED_FROM_SYSCALL)
        );
        // setuid changes ids, never the user namespace
        let mut escaped = user();
        escaped.user_ns = NS_CHILD;
        assert_eq!(
            judge_exit(&exit(
                abi::X64,
                nr::SETUID,
                user(),
                escaped,
                mech::COMMIT_CREDS
            )),
            Some(kind::CRED_FROM_SYSCALL)
        );
        // the 32-bit ioctl is judged on its own table: i386 54 is ioctl, not
        // x86_64 54 (setsockopt) — and i386 105 is no setuid
        assert_eq!(
            judge_commit(change::IDS, abi::IA32, nr32::IOCTL, true),
            Some(kind::CRED_FROM_SYSCALL)
        );
        assert_eq!(
            judge_commit(change::IDS, abi::IA32, nr::SETUID, true),
            Some(kind::CRED_FROM_SYSCALL)
        );
        assert_eq!(judge_commit(change::IDS, abi::X64, nr::SETUID, true), None);
        // outside any call
        assert_eq!(
            judge_commit(change::IDS, abi::NONE, 0, false),
            Some(kind::CRED_OUTSIDE_SYSCALL)
        );
        assert_eq!(judge_commit(0, abi::NONE, 0, false), None);
        // between calls
        assert_eq!(
            judge_enter(&user(), &root()),
            Some(kind::CRED_BETWEEN_SYSCALLS)
        );
        let mut capless = root();
        capless.cap_effective = 0;
        assert_eq!(judge_enter(&root(), &capless), None);
        assert_eq!(judge_enter(&user(), &user()), None);
    }

    #[test]
    fn namespace_root_and_fs_signatures() {
        let mut ns = exit(abi::X64, nr::IOCTL, user(), user(), 0);
        ns.nsproxy_changed = true;
        assert_eq!(judge_exit(&ns), Some(kind::NS_NO_MECHANISM));
        ns.mechanisms = mech::SWITCH_NS;
        assert_eq!(judge_exit(&ns), Some(kind::NS_FROM_SYSCALL));
        for n in [nr::SETNS, nr::UNSHARE] {
            ns.nr = n;
            assert_eq!(judge_exit(&ns), None, "nr {n}");
        }
        // clone's namespaces are the child's: a switch of the caller's is not
        ns.nr = nr::CLONE3;
        assert_eq!(judge_exit(&ns), Some(kind::NS_FROM_SYSCALL));
        assert_eq!(judge_switch_ns(abi::X64, nr::SETNS, true), None);
        assert_eq!(judge_switch_ns(abi::IA32, nr32::UNSHARE, true), None);
        assert_eq!(
            judge_switch_ns(abi::X64, nr::WRITE, true),
            Some(kind::NS_FROM_SYSCALL)
        );
        assert_eq!(
            judge_switch_ns(abi::NONE, 0, false),
            Some(kind::NS_FROM_SYSCALL)
        );

        // root: chroot and setns through set_fs_root, pivot_root through
        // chroot_fs_refs, another task's change on a shared fs_struct
        let mut r = exit(abi::X64, nr::WRITE, user(), user(), 0);
        r.root_changed = true;
        assert_eq!(judge_exit(&r), Some(kind::ROOT_NO_MECHANISM));
        r.root_epoch_advanced = true;
        assert_eq!(
            judge_exit(&r),
            None,
            "a sibling's chroot or a pivot_root in this mount namespace"
        );
        r.root_epoch_advanced = false;
        r.nr = nr::PIVOT_ROOT;
        assert_eq!(judge_exit(&r), None);
        r.nr = nr::CHROOT;
        r.mechanisms = mech::SET_FS_ROOT;
        assert_eq!(judge_exit(&r), None);
        r.nr = nr::SETNS;
        assert_eq!(judge_exit(&r), None);
        r.nr = nr::IOCTL;
        assert_eq!(judge_exit(&r), Some(kind::ROOT_FROM_SYSCALL));
        assert_eq!(judge_set_fs_root(abi::X64, nr::CHROOT, true), None);
        assert_eq!(
            judge_set_fs_root(abi::X64, nr::KEYCTL, true),
            Some(kind::ROOT_FROM_SYSCALL)
        );

        // fs_struct replaced: only unshare(CLONE_FS)
        let mut f = exit(abi::X64, nr::UNSHARE, user(), user(), 0);
        f.fs_changed = true;
        f.root_changed = true;
        assert_eq!(judge_exit(&f), None);
        f.nr = nr::WRITE;
        assert_eq!(judge_exit(&f), Some(kind::FS_SWAPPED));
    }

    /// Credentials win over namespaces when both changed (the classic
    /// escape: commit_creds(init_cred) then switch_task_namespaces(init)).
    #[test]
    fn credentials_are_judged_first() {
        let mut o = exit(abi::X64, nr::IOCTL, user(), root(), mech::ALL);
        o.nsproxy_changed = true;
        o.root_changed = true;
        assert_eq!(judge_exit(&o), Some(kind::CRED_FROM_SYSCALL));
        assert!(is_credential_kind(kind::CRED_FROM_SYSCALL));
        assert!(!is_credential_kind(kind::NS_FROM_SYSCALL));
        assert!(!is_credential_kind(kind::FS_SWAPPED));
    }

    #[test]
    fn abi_split() {
        assert_eq!(split_abi(nr::SETUID, false), (abi::X64, nr::SETUID));
        assert_eq!(split_abi(nr32::SETUID, true), (abi::IA32, nr32::SETUID));
        assert_eq!(
            split_abi(X32_SYSCALL_BIT | nr::SETUID, false),
            (abi::X32, nr::SETUID)
        );
        assert_eq!(split_abi(NO_SYSCALL, false), (abi::X64, NO_SYSCALL));
        assert_eq!(allowed(abi::X32, nr::SETUID), change::IDS);
        assert_eq!(allowed(abi::X64, NO_SYSCALL), 0);
        assert_eq!(allowed(abi::NONE, nr::SETUID), 0);
    }

    /// The table the eBPF programs judge through gives [`allowed`]'s answer
    /// for every ABI and every number, past the table's end included.
    #[test]
    fn allowed_table_is_allowed() {
        for a in [abi::X64, abi::IA32, abi::X32, abi::NONE, 7] {
            for n in (0..4096u32).chain([NO_SYSCALL, X32_SYSCALL_BIT | nr::SETUID]) {
                assert_eq!(allowed_in_table(a, n), allowed(a, n), "abi {a} nr {n}");
            }
        }
    }

    fn layout_6_8() -> ResolvedLayout {
        ResolvedLayout {
            task_cred: Some(3016),
            task_nsproxy: Some(3120),
            task_fs: Some(3096),
            task_ti_status: Some(16),
            fs_root: Some(24),
            path_dentry: Some(8),
            cred_uid: Some(8),
            cred_fsgid: Some(36),
            cred_cap_permitted: Some(56),
            cred_cap_effective: Some(64),
            cred_user_ns: Some(144),
            nsproxy_mnt: Some(24),
            nsproxy_pid: Some(32),
            nsproxy_net: Some(40),
            mnt_inum: Some(16),
            pid_inum: Some(128),
            net_inum: Some(136),
            user_inum: Some(232),
            task_real_cred: Some(3008),
            file_inode: Some(168),
            inode_mode: Some(0),
            inode_uid: Some(4),
            task_start_time: Some(2832),
            task_flags: Some(44),
        }
    }

    #[test]
    fn guard_config_checks_presence_and_layout() {
        let c =
            guard_config(&layout_6_8(), 40, cfg::MODE_DETECT, variant::STRICT).expect("6.8 layout");
        assert_eq!(c.armed, 0, "armed only once every program is attached");
        assert_eq!(c.fs_root_dentry, 32);
        assert_eq!(c.full_cap_mask, FULL);
        assert_eq!(core::mem::size_of::<GuardConfig>(), 128);
        assert_eq!(c.variant, variant::STRICT as u32);
        let lite = guard_config(&layout_6_8(), 40, cfg::MODE_DETECT, variant::LITE).expect("lite");
        assert_eq!((lite.task_real_cred, lite.inode_uid), (3008, 4));
        assert_eq!((lite.task_start_time, lite.task_flags), (2832, 44));
        assert_eq!(lite.armed_at_ns, 0, "the agent writes it once armed");
        let mut no_uid = layout_6_8();
        no_uid.inode_uid = None;
        assert!(guard_config(&no_uid, 40, cfg::MODE_DETECT, variant::LITE).is_err());
        assert!(guard_config(&no_uid, 40, cfg::MODE_DETECT, variant::STRICT).is_ok());
        let drop_lite_field: [fn(&mut ResolvedLayout); 2] =
            [|l| l.task_start_time = None, |l| l.task_flags = None];
        for f in drop_lite_field {
            let mut l = layout_6_8();
            f(&mut l);
            assert!(guard_config(&l, 40, cfg::MODE_DETECT, variant::LITE).is_err());
            assert!(guard_config(&l, 40, cfg::MODE_DETECT, variant::STRICT).is_ok());
        }
        assert!(guard_config(&layout_6_8(), 40, cfg::MODE_DETECT, 9).is_err());
        assert_eq!(core::mem::size_of::<LiteState>(), 88);
        assert_eq!(c.inject_comm_lo, 0, "no injection unless the lab asks");
        let mut comm = [0u8; 16];
        comm[..12].copy_from_slice(b"nn-epg-probe");
        let (lo, hi) = pack_comm(&comm);
        assert_eq!(lo, u64::from_le_bytes(*b"nn-epg-p"));
        assert_eq!(hi, u64::from_le_bytes(*b"robe\0\0\0\0"));
        // 5.15: atomic_t usage, u32 cap[2]: ids at 4, caps at 48 / 56
        let mut l = layout_6_8();
        l.cred_uid = Some(4);
        l.cred_fsgid = Some(32);
        l.cred_cap_permitted = Some(48);
        l.cred_cap_effective = Some(56);
        assert!(guard_config(&l, 40, cfg::MODE_ENFORCE, variant::STRICT).is_ok());
        // a missing field, an absent marker, a layout the reads would split
        let mut l = layout_6_8();
        l.task_ti_status = None;
        assert!(guard_config(&l, 40, cfg::MODE_DETECT, variant::STRICT).is_err());
        let mut l = layout_6_8();
        l.net_inum = Some(u32::MAX);
        assert!(guard_config(&l, 40, cfg::MODE_DETECT, variant::STRICT).is_err());
        let mut l = layout_6_8();
        l.cred_fsgid = Some(40);
        assert!(guard_config(&l, 40, cfg::MODE_DETECT, variant::STRICT).is_err());
        let mut l = layout_6_8();
        l.cred_cap_effective = Some(72);
        assert!(guard_config(&l, 40, cfg::MODE_DETECT, variant::STRICT).is_err());
        assert!(guard_config(&layout_6_8(), 40, 7, variant::STRICT).is_err());
    }

    /// Lite: the use points. Every legitimate change went through a
    /// mechanism that updated the committed snapshot, so a use with what the
    /// committed one does not hold is the in-place write; a fully privileged
    /// committed task is skipped.
    #[test]
    fn lite_use_points() {
        const NS_A: u64 = 0xffff_0000_0000_a000;
        const NS_B: u64 = 0xffff_0000_0000_b000;
        // legitimate: the committed snapshot followed the change
        assert_eq!(judge_use(&root(), &root(), NS_A, NS_A), None);
        assert_eq!(judge_use(&user(), &user(), NS_A, NS_A), None);
        // becoming another user with no mechanism is a write in place too
        // (a fully privileged committed task never gets here: lite_skips)
        assert_eq!(
            judge_use(&root(), &user(), NS_A, NS_A),
            Some(kind::CRED_NO_MECHANISM)
        );
        // losing capabilities is not
        let mut capless = user();
        capless.cap_permitted = 0;
        assert_eq!(judge_use(&user(), &capless, NS_A, NS_A), None);
        // the in-place write, caught at the first capable() / exec / open
        let mut flipped = user();
        flipped.ids[id::UID] = 0;
        flipped.ids[id::EUID] = 0;
        flipped.ids[id::FSUID] = 0;
        assert_eq!(
            judge_use(&user(), &flipped, NS_A, NS_A),
            Some(kind::CRED_NO_MECHANISM)
        );
        let mut caps = user();
        caps.cap_effective = 1 << 21;
        caps.cap_permitted = 1 << 21;
        assert_eq!(
            judge_use(&user(), &caps, NS_A, NS_A),
            Some(kind::CRED_NO_MECHANISM)
        );
        // another nsproxy with no switch_task_namespaces (the escape's
        // pointer swap); an unknown committed nsproxy is not judged
        assert_eq!(
            judge_use(&user(), &user(), NS_A, NS_B),
            Some(kind::NS_NO_MECHANISM)
        );
        assert_eq!(judge_use(&user(), &user(), 0, NS_B), None);
        // credentials first
        assert_eq!(
            judge_use(&user(), &flipped, NS_A, NS_B),
            Some(kind::CRED_NO_MECHANISM)
        );
        // skip: committed root with every capability; not root with fewer
        assert!(lite_skips(&root(), FULL));
        assert!(!lite_skips(&user(), FULL));
        assert!(
            !lite_skips(&setuid_root_image(), FULL),
            "a setuid image keeps the user's ruid"
        );
        assert!(point::is_use_point(point::CAPABLE));
        assert!(point::is_use_point(point::FILE_OPEN));
        assert!(!point::is_use_point(point::SYS_EXIT));
        assert!(!point::is_use_point(point::COMMIT_CREDS));
    }

    #[test]
    fn lite_file_open_filter_and_call_decode() {
        // root-owned, not world-readable: /etc/shadow 0640, /root 0700
        assert!(file_open_is_guarded(0, 0o100640));
        assert!(file_open_is_guarded(0, 0o040700));
        // world-readable, or not root's: no lookup
        assert!(!file_open_is_guarded(0, 0o100644));
        assert!(!file_open_is_guarded(1000, 0o100600));
        // orig_ax: a call, a 32-bit call, an x32 call, none (interrupt entry)
        assert_eq!(
            syscall_of(nr::SETUID as u64, false),
            Some((abi::X64, nr::SETUID))
        );
        assert_eq!(
            syscall_of(nr32::SETUID as u64, true),
            Some((abi::IA32, nr32::SETUID))
        );
        assert_eq!(
            syscall_of((X32_SYSCALL_BIT | nr::SETNS) as u64, false),
            Some((abi::X32, nr::SETNS))
        );
        assert_eq!(syscall_of(u64::MAX, false), None);
        assert_eq!(syscall_of((-33i64) as u64, false), None);
        // in lite the mechanism hooks judge that call
        let (a, n) = syscall_of(nr::IOCTL as u64, false).unwrap();
        assert_eq!(
            judge_commit(change::IDS, a, n, true),
            Some(kind::CRED_FROM_SYSCALL)
        );
        assert_eq!(PT_REGS_ORIG_AX, 15 * 8);
    }

    /// Lite's task map is an LRU hash keyed by the `task_struct` address:
    /// a record is the task's only while its start time says so, an exec by
    /// a non-leader thread keeps it, and a task started after arming that
    /// has none lost it (degraded evidence when it holds privilege).
    #[test]
    fn lite_records_survive_reuse_and_thread_exec() {
        const T0: u64 = 5_000_000_000;
        assert_eq!(lite_entry(T0, T0), LiteEntry::Current);
        // de_thread: the exec'ing thread takes its (older) leader's start
        assert_eq!(lite_entry(T0 + 10, T0), LiteEntry::ThreadExec);
        // a later task at the address an earlier one left its record at
        assert_eq!(lite_entry(T0, T0 + 10), LiteEntry::Stale);

        const ARMED: u64 = 9_000_000_000;
        // started before arming: first seen, not lost
        assert!(!baseline_lost(ARMED - 1, 0, ARMED));
        // started after: the armed fork program took its baseline
        assert!(baseline_lost(ARMED, 0, ARMED));
        assert!(baseline_lost(ARMED + 1, 0x0040_0040, ARMED));
        // io_uring and vhost workers have no fork tracepoint
        assert!(!baseline_lost(ARMED + 1, PF_IO_WORKER, ARMED));
        assert!(!baseline_lost(ARMED + 1, PF_USER_WORKER, ARMED));
        // before the agent wrote the arming time nothing is called lost
        assert!(!baseline_lost(ARMED + 1, 0, 0));

        // what a re-taken snapshot must hold to be recorded
        assert!(!holds_privilege(&user()));
        assert!(holds_privilege(&root()));
        assert!(holds_privilege(&setuid_root_image()));
        let mut flipped = user();
        flipped.ids[id::FSUID] = 0;
        assert!(
            holds_privilege(&flipped),
            "fsuid 0 alone reads root's files"
        );
        let mut gid0 = user();
        gid0.ids[id::SGID] = 0;
        assert!(holds_privilege(&gid0));
        let mut caps = user();
        caps.cap_permitted = 1 << 21;
        assert!(holds_privilege(&caps));
        caps.cap_permitted = 0;
        caps.cap_effective = 1 << 12;
        assert!(holds_privilege(&caps));
        assert_eq!(
            counter::NAMES[counter::BASELINES_LOST as usize],
            "baselines_lost"
        );
    }

    /// The table, one row per call that may change anything: the agent's
    /// documentation and this test read the same `allowed`.
    #[test]
    fn the_table_lists_exactly_these_calls() {
        let mut x64 = [0u32; 512];
        let mut n = 0;
        for c in 0..512u32 {
            if allowed(abi::X64, c) != 0 {
                x64[n] = c;
                n += 1;
            }
        }
        assert_eq!(
            &x64[..n],
            &[
                nr::EXECVE,
                nr::SETUID,
                nr::SETGID,
                nr::SETREUID,
                nr::SETREGID,
                nr::SETGROUPS,
                nr::SETRESUID,
                nr::SETRESGID,
                nr::SETFSUID,
                nr::SETFSGID,
                nr::CAPSET,
                nr::PIVOT_ROOT,
                nr::CHROOT,
                nr::UNSHARE,
                nr::SETNS,
                nr::EXECVEAT,
            ]
        );
        let ia32 = (0..512u32).filter(|c| allowed(abi::IA32, *c) != 0).count();
        assert_eq!(ia32, 25);
        // no call grants a credential change it cannot make through
        // commit_creds, and only unshare an fs_struct
        for c in 0..512u32 {
            for a in [abi::X64, abi::IA32, abi::X32] {
                let al = allowed(a, c);
                if al & change::FS != 0 {
                    assert!(c == nr::UNSHARE || c == nr32::UNSHARE, "{a} {c}");
                }
            }
        }
        assert_eq!(mechanism_for(change::IDS), mech::COMMIT_CREDS);
        assert_eq!(mechanism_for(change::NSPROXY), mech::SWITCH_NS);
        assert_eq!(mechanism_for(change::ROOT), mech::SET_FS_ROOT);
        assert_eq!(mechanism_for(change::FS), 0);
        assert_eq!(counter::NAMES.len() as u32, counter::SLOTS);
        assert_eq!(
            counter::NAMES[counter::LAZY_BASELINES as usize],
            "lazy_baselines"
        );
    }
}
