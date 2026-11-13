//! Lot 280a: the guarded sysctls judged on the value the kernel will apply
//! — a `cgroup/sysctl` program, attached to the ROOT cgroup (every task's
//! default-hierarchy cgroup descends from it).
//!
//! Lot 273d's write deny (`cgroup_files::refuse_sysctl`, `file_permission`)
//! reads the bytes of the write from the writer's memory before the kernel
//! copies them: a second thread can change them in between. This program
//! runs inside `proc_sys_call_handler`, after the kernel has duplicated the
//! buffer and before the handler parses that same copy, so the value it
//! reads (`bpf_sysctl_get_new_value`) is the one the kernel applies; it
//! reads it as the kernel does, `bpf_strtol` in base 0 (octal after a `0`,
//! hexadecimal after `0x`, leading blanks skipped). The verdict is the
//! shared module's (`northnarrow_common::sysctl_judge`), the floors the
//! write deny's: outside the agent's family and a signed trusted-installer
//! window a harmful value is refused (`EPERM`), a write of
//! `kernel.ftrace_enabled` or `kernel.sched_rt_period_us` too whatever it
//! carries, and a value it cannot read; the signed opt-out
//! ([`SYSCTL_OPTOUT`]) lets its range through, every such write recorded.
//!
//! Lot 341: a host-wide deny ([`crate::host_deny`]): under the start's
//! `alpha` profile a refused value goes through,
//! signed "would deny".
//!
//! A program in a child cgroup cannot get around it: the agent attaches it
//! by a link, which the kernel attaches `BPF_F_ALLOW_MULTI`
//! (`cgroup_bpf_link_attach`), so the root's program is in every
//! descendant's effective array whatever a child attaches; that array runs
//! the descendants' programs first and the root's last, any program's 0 is
//! `EPERM` for the write, and a child's `bpf_sysctl_set_new_value` rewrites
//! the very copy this program then reads.
//!
//! The 5.15 helpers of a `cgroup/sysctl` program include neither
//! `bpf_get_current_pid_tgid` nor `bpf_get_current_comm` (6.1+): the
//! writer's tgid and comm are read from its task.

use aya_ebpf::{
    cty::{c_char, c_long},
    helpers::{bpf_get_current_task, bpf_probe_read_kernel, generated},
    macros::{cgroup_sysctl, map},
    maps::Array,
    programs::SysctlContext,
};
use northnarrow_common::cgroup_limits::SYSCTL_NONE;
use northnarrow_common::sysctl_judge::{
    record_dev, sysctl_path_kind, verdict_of, Range, SysctlOptOut, SysctlVerdict,
    SYSCTL_OPTOUT_SLOTS, SYSCTL_PATH_MAX,
};
use northnarrow_common::wire::{InodeKey, FS_OP_SYSCTL_OPT_OUT, FS_OP_SYSCTL_VALUE, TASK_COMM_LEN};

use crate::btf_offsets::{TASK_STRUCT_COMM_OFFSET, TASK_STRUCT_TGID_OFFSET};

/// The signed per-sysctl opt-out, indexed by kind: the range a policy the
/// agent verified allows, bound to this boot's session nonce
/// (`SysctlOptOut::live`). Written by the agent only (a foreign write
/// handle is the BPF guard's to refuse); the write deny reads it too.
/// Pinned by name, like `FS_GRANT`.
#[map]
pub static SYSCTL_OPTOUT: Array<SysctlOptOut> = Array::pinned(SYSCTL_OPTOUT_SLOTS, 0);

/// `[0]` = 1 once the agent attached [`nn_sysctl_guard`] on the root cgroup
/// this boot: the write deny then leaves the opt-out's record to it (one
/// record a write). Per boot, like the denials' ring both write to.
#[map]
pub static SYSCTL_KERNEL_JUDGE: Array<u32> = Array::with_max_entries(1, 0);

/// The new value's buffer: a longer write (`-E2BIG`) is not read, so
/// refused — the kernel itself reads at most 21 characters of an integer.
const VALUE_BUF: usize = 64;

/// `bpf_strtol`'s flags: base 0, the kernel's own reading of a sysctl.
const BASE_0: u64 = 0;

/// 1 lets the access through, 0 is `EPERM`.
#[cgroup_sysctl]
pub fn nn_sysctl_guard(ctx: SysctlContext) -> i32 {
    match unsafe { try_sysctl_guard(&ctx) } {
        SysctlVerdict::Refuse => 0,
        SysctlVerdict::Allow | SysctlVerdict::OptedOut => 1,
    }
}

#[inline(always)]
unsafe fn try_sysctl_guard(ctx: &SysctlContext) -> SysctlVerdict {
    // a read is no change
    if (*ctx.sysctl).write == 0 {
        return SysctlVerdict::Allow;
    }
    let kind = sysctl_of(ctx);
    if kind == SYSCTL_NONE {
        return SysctlVerdict::Allow;
    }
    let task = bpf_get_current_task() as *const u8;
    let tgid = bpf_probe_read_kernel::<u32>(task.add(off!(TASK_STRUCT_TGID_OFFSET)) as *const u32)
        .unwrap_or(0);
    // the identity every guarded write is let through by: the agent's
    // family (its round's restore), a signed window; an unread tgid is no
    // one's (0 is never an exempt pid)
    let caller_may = (tgid != 0 && crate::task_kill::is_exempt_pid(tgid))
        || crate::inode_protect::override_active();
    if caller_may {
        return SysctlVerdict::Allow;
    }
    // every value written (no `Option`: lot 280a's first lab round, `R2
    // !read_ok` — `common::sysctl_judge::Range`)
    let (read, v) = new_value(ctx);
    let verdict = verdict_of(kind, false, read, v, opt_out(kind));
    match verdict {
        SysctlVerdict::Refuse => {
            // Lot 341: a host-wide deny (`crate::host_deny`) — under the
            // `alpha` profile the write goes through, signed "would deny"
            let (refuse, op) = crate::host_deny::judge_no_task(FS_OP_SYSCTL_VALUE);
            record(op, kind, read, v, task, tgid, true);
            if !refuse {
                return SysctlVerdict::Allow;
            }
        }
        SysctlVerdict::OptedOut => record(FS_OP_SYSCTL_OPT_OUT, kind, read, v, task, tgid, false),
        SysctlVerdict::Allow => {}
    }
    verdict
}

/// The guarded sysctl the access names (its path under `/proc/sys`, read
/// into a zeroed buffer: the words past the name and its NUL stay zero),
/// or `SYSCTL_NONE` — a name of [`SYSCTL_PATH_MAX`] bytes or more is
/// `-E2BIG`, never one of ours.
#[inline(always)]
unsafe fn sysctl_of(ctx: &SysctlContext) -> u8 {
    let mut name = [0u64; 4];
    let n = generated::bpf_sysctl_get_name(
        ctx.sysctl,
        name.as_mut_ptr() as *mut c_char,
        SYSCTL_PATH_MAX as u64,
        0,
    );
    if n <= 0 || n as usize >= SYSCTL_PATH_MAX {
        return SYSCTL_NONE;
    }
    sysctl_path_kind(n as usize, name)
}

/// The kernel's copy of the write, read in base 0 as the kernel reads it:
/// `(true, value)`, or `(false, 0)` when it is longer than [`VALUE_BUF`] -
/// 1 bytes, not an integer, or past `i64` (refused).
#[inline(always)]
unsafe fn new_value(ctx: &SysctlContext) -> (bool, i64) {
    let mut buf = core::mem::MaybeUninit::<[u8; VALUE_BUF]>::uninit();
    let p = buf.as_mut_ptr() as *mut c_char;
    // zero-filled past the value by the helper; -E2BIG when cut
    if generated::bpf_sysctl_get_new_value(ctx.sysctl, p, VALUE_BUF as u64) < 0 {
        return (false, 0);
    }
    let mut res: c_long = 0;
    if generated::bpf_strtol(p, VALUE_BUF as u64, BASE_0, &mut res) < 0 {
        return (false, 0);
    }
    (true, res as i64)
}

/// The signed opt-out's range in force for `kind` (`Range::NONE`: none).
#[inline(always)]
pub(crate) fn opt_out(kind: u8) -> Range {
    let session = match crate::task_kill::AGENT_SESSION.get(0) {
        Some(s) => *s,
        None => return Range::NONE,
    };
    match SYSCTL_OPTOUT.get(kind as u32) {
        Some(slot) => slot.range(session),
        None => Range::NONE,
    }
}

/// Whether this boot's agent attached [`nn_sysctl_guard`] on the root
/// cgroup (the write deny's question).
#[inline(always)]
pub(crate) fn kernel_judge_attached() -> bool {
    matches!(SYSCTL_KERNEL_JUDGE.get(0), Some(v) if *v == 1)
}

/// Sign the write: the kind and the value (or that it was not read), the
/// writer's tgid and comm read from its task.
#[inline(always)]
unsafe fn record(
    operation: u8,
    kind: u8,
    read: bool,
    v: i64,
    task: *const u8,
    tgid: u32,
    limited: bool,
) {
    let comm = bpf_probe_read_kernel::<[u8; TASK_COMM_LEN]>(
        task.add(off!(TASK_STRUCT_COMM_OFFSET)) as *const [u8; TASK_COMM_LEN],
    )
    .unwrap_or([0u8; TASK_COMM_LEN]);
    crate::inode_protect::emit_sysctl_record(
        operation,
        InodeKey {
            dev: record_dev(kind, read),
            ino: v as u64,
        },
        tgid,
        comm,
        limited,
    );
}
