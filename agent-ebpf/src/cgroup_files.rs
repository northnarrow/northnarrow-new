//! Lot 273b — writes that stop the agent without a signal, refused at the
//! write-open (`file_open`) and at the write itself (`file_permission`, for
//! a descriptor opened before the inode was protected):
//!
//! * a resource file of a protected unit's cgroup or of an ancestor slice
//!   (`memory.max`, `cpu.max`, `pids.max`, …: [`northnarrow_common::cgroup_limits`])
//!   — protected by name under a directory registered with
//!   `FS_PROTECT_LIMIT_DIR`, so a file that appears later (a controller
//!   enabled after the registration) is covered too. Refused to every
//!   caller outside the agent's family but PID 1; PID 1 (systemd realising
//!   the unit, `systemctl set-property`) may put back the value the file
//!   held at the registration ([`LIMIT_VALUES`], or the kernel's default
//!   for a file that appeared later), read from the `write(2)` that
//!   carries it;
//! * a cgroup v1 hierarchy, on a host whose systemd runs the unified one
//!   only ([`CGROUP_POLICY`]): a root could mount the v1 `freezer`, move the
//!   agent there through the v1 `cgroup.procs` (which checks no inode the
//!   move guard sees) and freeze it;
//! * a protected process's `oom_score_adj` / `oom_adj`: `1000` makes it the
//!   OOM killer's first choice, whose SIGKILL no `task_kill` hook sees.
//!
//! Outside a signed trusted-installer window only, like every deny.

use aya_ebpf::{
    cty::c_void,
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel, generated},
    macros::map,
    maps::{Array, HashMap},
};
use northnarrow_common::cgroup_limits::{
    default_value, limit_kind, same_value, strip_newline, word_mask, LimitValue, LIMIT_NAME_MAX,
    LIMIT_NONE, LIMIT_TEXT_MAX,
};
use northnarrow_common::wire::{
    InodeKey, CGROUP2_SUPER_MAGIC, CGROUP_POLICY_V1_REFUSE, CGROUP_SUPER_MAGIC,
    FS_OP_CGROUP_LIMIT, FS_OP_CGROUP_V1, FS_OP_OOM_ADJ, FS_PROTECT_LIMIT_DIR, PROC_SUPER_MAGIC,
};

use crate::btf_offsets::{
    DENTRY_D_INODE_OFFSET, DENTRY_D_NAME_OFFSET, DENTRY_D_PARENT_OFFSET, FILE_F_PATH_OFFSET,
    INODE_I_SB_OFFSET, PATH_DENTRY_OFFSET, PID_TASKS_OFFSET, PROC_INODE_PID_OFFSET,
    PROC_INODE_VFS_INODE_OFFSET, PT_REGS_DX_OFFSET, PT_REGS_ORIG_AX_OFFSET, PT_REGS_SI_OFFSET,
    QSTR_LEN_OFFSET, QSTR_NAME_OFFSET, SUPER_BLOCK_S_MAGIC_OFFSET, TASK_STRUCT_PID_LINKS_OFFSET,
    TASK_STRUCT_TGID_OFFSET,
};

/// The value each protected resource file held when the agent registered
/// its cgroup (`northnarrow_common::cgroup_limits::limit_value`): the one
/// write PID 1 may make. A file without an entry has the kernel's default
/// for its kind. Pinned by name, like `PROTECTED_INODES`.
#[map]
pub static LIMIT_VALUES: HashMap<InodeKey, LimitValue> = HashMap::pinned(512, 0);

/// `[0]`: `CGROUP_POLICY_*` bits written by the agent at its attach
/// (`CGROUP_POLICY_V1_REFUSE`). Pinned by name.
#[map]
pub static CGROUP_POLICY: Array<u32> = Array::pinned(1, 0);

/// Where the write is judged: at the open (`file_open`) or at a write
/// (`file_permission`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    Open,
    Write,
}

/// `__NR_write` and `__NR_pwrite64` on x86-64: the calls whose buffer and
/// count are the second and third arguments.
const NR_WRITE: u64 = 1;
const NR_PWRITE64: u64 = 18;

/// `true` when the write of `file` (whose inode is `inode`) must be
/// refused; the refusal is signed here. `hook` is the caller's
/// `DENY_FAIL_OPEN` slot.
#[inline(always)]
pub(crate) unsafe fn refuse_write(
    file: *const c_void,
    inode: *const c_void,
    hook: u32,
    phase: Phase,
) -> bool {
    if inode.is_null() {
        return false;
    }
    let sb = match bpf_probe_read_kernel::<*const c_void>(
        (inode as *const u8).add(off!(INODE_I_SB_OFFSET)) as *const *const c_void,
    ) {
        Ok(p) if !p.is_null() => p,
        _ => {
            crate::fail_open::bump(hook);
            return false;
        }
    };
    let magic = match bpf_probe_read_kernel::<u64>(
        (sb as *const u8).add(off!(SUPER_BLOCK_S_MAGIC_OFFSET)) as *const u64,
    ) {
        Ok(m) => m,
        Err(_) => {
            crate::fail_open::bump(hook);
            return false;
        }
    };
    // `s_magic` is an `unsigned long`; the magics are 32-bit.
    let magic = magic & 0xffff_ffff;
    if magic == CGROUP2_SUPER_MAGIC {
        refuse_limit(file, inode, hook, phase)
    } else if magic == CGROUP_SUPER_MAGIC {
        refuse_v1(inode, hook, phase)
    } else if magic == PROC_SUPER_MAGIC {
        refuse_oom_adj(file, inode, phase)
    } else {
        false
    }
}

/// The dentry of `file` (`file->f_path.dentry`).
#[inline(always)]
unsafe fn file_dentry(file: *const c_void) -> Option<*const c_void> {
    let p = bpf_probe_read_kernel::<*const c_void>(
        (file as *const u8).add(off!(FILE_F_PATH_OFFSET) + off!(PATH_DENTRY_OFFSET))
            as *const *const c_void,
    )
    .ok()?;
    (!p.is_null()).then_some(p)
}

/// The name of `dentry` as [`northnarrow_common::cgroup_limits::name_words`]
/// packs it: `(len, words)`, `None` for a name longer than
/// [`LIMIT_NAME_MAX`] or one that cannot be read.
#[inline(always)]
unsafe fn dentry_name_words(dentry: *const c_void) -> Option<(usize, [u64; 3])> {
    let qstr = (dentry as *const u8).add(off!(DENTRY_D_NAME_OFFSET));
    let len = bpf_probe_read_kernel::<u32>(qstr.add(off!(QSTR_LEN_OFFSET)) as *const u32).ok()?
        as usize;
    if len == 0 || len > LIMIT_NAME_MAX {
        return None;
    }
    let name = bpf_probe_read_kernel::<*const u8>(qstr.add(off!(QSTR_NAME_OFFSET)) as *const *const u8)
        .ok()?;
    if name.is_null() {
        return None;
    }
    // A short name lives in the dentry's inline array, whose size is larger
    // than the three words read: the bytes past the name are cleared.
    let raw = bpf_probe_read_kernel::<[u64; 3]>(name as *const [u64; 3]).ok()?;
    Some((
        len,
        [
            raw[0] & word_mask(len, 0),
            raw[1] & word_mask(len, 1),
            raw[2] & word_mask(len, 2),
        ],
    ))
}

/// The caller outside the agent's family and outside a window: the only
/// one a refusal is for.
#[inline(always)]
fn caller_may(caller: u32) -> bool {
    crate::task_kill::is_exempt_pid(caller) || crate::inode_protect::override_active()
}

/// A resource file of a protected cgroup: [`refuse_write`]'s cgroup v2
/// half.
#[inline(always)]
unsafe fn refuse_limit(file: *const c_void, inode: *const c_void, hook: u32, phase: Phase) -> bool {
    let Some(dentry) = file_dentry(file) else {
        return false;
    };
    let Some((len, words)) = dentry_name_words(dentry) else {
        return false;
    };
    let kind = limit_kind(len, words);
    if kind == LIMIT_NONE {
        return false;
    }
    // Its directory: a protected unit's or slice's?
    let parent = match bpf_probe_read_kernel::<*const c_void>(
        (dentry as *const u8).add(off!(DENTRY_D_PARENT_OFFSET)) as *const *const c_void,
    ) {
        Ok(p) if !p.is_null() => p,
        _ => {
            crate::fail_open::bump(hook);
            return false;
        }
    };
    let dir = match bpf_probe_read_kernel::<*const c_void>(
        (parent as *const u8).add(off!(DENTRY_D_INODE_OFFSET)) as *const *const c_void,
    ) {
        Ok(p) if !p.is_null() => p,
        _ => {
            crate::fail_open::bump(hook);
            return false;
        }
    };
    let Some(dir_key) = crate::inode_protect::read_inode_key(dir) else {
        crate::fail_open::bump(hook);
        return false;
    };
    match crate::inode_protect::PROTECTED_INODES.get(&dir_key) {
        Some(f) if *f & FS_PROTECT_LIMIT_DIR != 0 => {}
        _ => return false,
    }
    let caller = (bpf_get_current_pid_tgid() >> 32) as u32;
    if caller_may(caller) {
        return false;
    }
    let Some(key) = crate::inode_protect::read_inode_key(inode) else {
        crate::fail_open::bump(hook);
        return false;
    };
    if caller == 1 {
        // systemd realising the unit or applying a `set-property`: the
        // open is let through, the value judged at the write.
        if phase == Phase::Open {
            return false;
        }
        let value = match LIMIT_VALUES.get(&key) {
            Some(v) => Some(*v),
            None => default_value(kind),
        };
        if let (Some(value), Some(written)) = (value, written_value()) {
            if same_value(&written, &value) {
                return false;
            }
        }
    }
    sign(phase, FS_OP_CGROUP_LIMIT, key);
    true
}

/// The bytes the current `write(2)` / `pwrite64(2)` carries, zero past
/// its count (as `northnarrow_common::cgroup_limits::limit_value` packs a
/// text); `None` when they cannot be read — another call, more than
/// `LIMIT_TEXT_MAX` bytes, another architecture: PID 1's write is then
/// refused.
#[inline(always)]
pub(crate) unsafe fn written_value() -> Option<LimitValue> {
    written_bytes().map(|(v, n)| strip_newline(v, n as usize))
}

/// [`written_value`]'s bytes and count, the newline kept.
#[inline(always)]
unsafe fn written_bytes() -> Option<(LimitValue, u32)> {
    let si = off_opt!(PT_REGS_SI_OFFSET)?;
    let dx = off_opt!(PT_REGS_DX_OFFSET)?;
    let ax = off_opt!(PT_REGS_ORIG_AX_OFFSET)?;
    if si > 0xff || dx > 0xff || ax > 0xff {
        return None;
    }
    let task = generated::bpf_get_current_task_btf();
    let regs = generated::bpf_task_pt_regs(task) as *const u8;
    if regs.is_null() {
        return None;
    }
    let nr = bpf_probe_read_kernel::<u64>(regs.add(ax) as *const u64).ok()?;
    if nr != NR_WRITE && nr != NR_PWRITE64 {
        return None;
    }
    let buf = bpf_probe_read_kernel::<u64>(regs.add(si) as *const u64).ok()?;
    let count = bpf_probe_read_kernel::<u64>(regs.add(dx) as *const u64).ok()?;
    // A value and systemd's newline: at most LIMIT_TEXT_MAX + 1 bytes.
    if count == 0 || count > LIMIT_TEXT_MAX as u64 + 1 {
        return None;
    }
    let mut value: LimitValue = [0u64; 4];
    // Bounded for the verifier: 1 to 32 bytes into the 32 of `value`.
    let n = (count as u32) & 63;
    if n == 0 || n > 32 {
        return None;
    }
    if generated::bpf_probe_read_user(value.as_mut_ptr() as *mut c_void, n, buf as *const c_void)
        != 0
    {
        return None;
    }
    Some((value, n))
}

/// A cgroup v1 hierarchy: [`refuse_write`]'s v1 half.
#[inline(always)]
unsafe fn refuse_v1(inode: *const c_void, hook: u32, phase: Phase) -> bool {
    match CGROUP_POLICY.get(0) {
        Some(p) if *p & CGROUP_POLICY_V1_REFUSE != 0 => {}
        _ => return false,
    }
    let caller = (bpf_get_current_pid_tgid() >> 32) as u32;
    if caller_may(caller) {
        return false;
    }
    let Some(key) = crate::inode_protect::read_inode_key(inode) else {
        crate::fail_open::bump(hook);
        return false;
    };
    sign(phase, FS_OP_CGROUP_V1, key);
    true
}

/// `oom_score_adj` / `oom_adj` of a protected process: [`refuse_write`]'s
/// procfs half. Not armed without the proc offsets (the agent signs that
/// degradation); a read that fails is not a fail-open of the hook: the
/// file is then no protected process's.
#[inline(always)]
unsafe fn refuse_oom_adj(file: *const c_void, inode: *const c_void, phase: Phase) -> bool {
    let Some(dentry) = file_dentry(file) else {
        return false;
    };
    let Some((len, words)) = dentry_name_words(dentry) else {
        return false;
    };
    // "oom_score_adj" (13 bytes) or "oom_adj" (7).
    const OOM_SCORE_ADJ: [u64; 3] = northnarrow_common::cgroup_limits::name_words(b"oom_score_adj");
    const OOM_ADJ: [u64; 3] = northnarrow_common::cgroup_limits::name_words(b"oom_adj");
    let named = (len == 13 && words[0] == OOM_SCORE_ADJ[0] && words[1] == OOM_SCORE_ADJ[1])
        || (len == 7 && words[0] == OOM_ADJ[0]);
    if !named {
        return false;
    }
    let Some(tgid) = proc_file_tgid(inode) else {
        return false;
    };
    if !crate::task_kill::is_protected_pid(tgid) {
        return false;
    }
    let caller = (bpf_get_current_pid_tgid() >> 32) as u32;
    if caller_may(caller) {
        return false;
    }
    let _ = phase;
    crate::inode_protect::emit_task_denial(FS_OP_OOM_ADJ, 0, tgid);
    true
}

/// The tgid of the process a `/proc/<pid>/…` (or `/proc/<pid>/task/<tid>/…`)
/// file belongs to: `proc_inode->pid`'s task, and that task's tgid.
#[inline(always)]
unsafe fn proc_file_tgid(inode: *const c_void) -> Option<u32> {
    let vfs = off_opt!(PROC_INODE_VFS_INODE_OFFSET)?;
    let pid_off = off_opt!(PROC_INODE_PID_OFFSET)?;
    let tasks = off_opt!(PID_TASKS_OFFSET)?;
    let links = off_opt!(TASK_STRUCT_PID_LINKS_OFFSET)?;
    // Bounded, as `inode_dev::stat_dev` explains: the verifier refuses an
    // unbounded offset on a BTF-typed pointer.
    if vfs > 0xffff || pid_off > 0xffff || links > 0xffff {
        return None;
    }
    let proc_inode = (inode as *const u8).wrapping_sub(vfs);
    let pid = bpf_probe_read_kernel::<*const u8>(proc_inode.wrapping_add(pid_off) as *const *const u8)
        .ok()?;
    if pid.is_null() {
        return None;
    }
    // `pid->tasks[PIDTYPE_PID].first`: the task's `pid_links[PIDTYPE_PID]`.
    let node = bpf_probe_read_kernel::<*const u8>(pid.add(tasks) as *const *const u8).ok()?;
    if node.is_null() {
        return None;
    }
    let task = node.wrapping_sub(links);
    bpf_probe_read_kernel::<u32>(task.add(off!(TASK_STRUCT_TGID_OFFSET)) as *const u32).ok()
}

/// Sign a refusal: at the open once per attempt, at a write rate-limited
/// per caller (a loop of writes on one descriptor is one record a second).
#[inline(always)]
fn sign(phase: Phase, operation: u8, key: InodeKey) {
    match phase {
        Phase::Open => crate::inode_protect::emit_denial(operation, key),
        Phase::Write => crate::inode_protect::emit_limited(operation, key),
    }
}
