//! Tappa 10.9 step 2 — the exec sensor on LSM `bprm_check_security`.
//!
//! Design: `docs/design/TAPPA10_9_SENSOR_ATTACH_POINTS_DESIGN.md` §11.
//! For each binfmt pass (a `#!` script: the script, then its interpreter)
//! [`exec_check_lsm`] reads the file the kernel opened, `bprm->file`: its
//! `(dev, ino)`, memory-backed filesystem, memfd name, link count, and its
//! path rebuilt from the dentry up to the exec'ing task's root or the
//! filesystem's root ([`nn_exe_walk`]). Review 61: the exec rules matched
//! the caller's string (`./x`, a symlink, `..`) instead.
//!
//! It emits an `ExecCheckRaw` per pass into the exec-check ring (the one
//! `sys_enter_execve` writes in tracepoint mode). On pass 0, the file the
//! caller named, it also leaves the identity in [`EXEC_HANDOFF`] for
//! `sched_process_exec`, which runs in the same task once the exec has
//! succeeded and appends it to `ProcessSpawnRaw`. Observe only: the
//! program always returns 0 (Q4: the deny belongs to the 10.9
//! inline-enforcement item).
use aya_ebpf::{
    cty::c_void,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task,
        bpf_get_current_uid_gid, bpf_ktime_get_ns, gen,
    },
    macros::{lsm, map},
    maps::{LruHashMap, PerCpuArray},
    programs::LsmContext,
};
use northnarrow_common::wire::exe::{
    exe_flags, exe_path_slot, ExeIdentityRaw, EXE_PATH_SLOTS, EXE_PATH_SLOT_LEN, EXE_WALK_DEPTH,
};
use northnarrow_common::wire::{ExecCheckRaw, FILENAME_LEN, TASK_COMM_LEN};

use crate::btf_offsets::{
    DENTRY_D_INODE_OFFSET, DENTRY_D_NAME_OFFSET, DENTRY_D_PARENT_OFFSET, FILE_F_INODE_OFFSET,
    FILE_F_PATH_OFFSET, FS_STRUCT_ROOT_OFFSET, INODE_I_INO_OFFSET, INODE_I_NLINK_OFFSET,
    INODE_I_SB_OFFSET, LINUX_BINPRM_FILENAME_OFFSET, LINUX_BINPRM_FILE_OFFSET,
    LINUX_BINPRM_INTERP_OFFSET, PATH_DENTRY_OFFSET, QSTR_NAME_OFFSET, SUPER_BLOCK_S_DEV_OFFSET,
    SUPER_BLOCK_S_MAGIC_OFFSET, TASK_STRUCT_FS_OFFSET, TASK_STRUCT_REAL_PARENT_OFFSET,
    TASK_STRUCT_TGID_OFFSET,
};

/// Memory-backed filesystems (`TMPFS` flag): tmpfs, hugetlbfs, ramfs.
const TMPFS_MAGIC: u64 = 0x0102_1994;
const HUGETLBFS_MAGIC: u64 = 0x9584_58f6;
const RAMFS_MAGIC: u64 = 0x8584_58f6;
/// "memfd:" as the low six bytes of a little-endian u64.
const MEMFD_PREFIX: u64 = 0x3a64_666d_656d;
const MEMFD_MASK: u64 = 0xffff_ffff_ffff;

/// Pass 0's identity, keyed by the exec'ing `task_struct`, until
/// `sched_process_exec` takes it. A failed exec leaves an entry that the
/// task's next exec overwrites at its own pass 0; the LRU bounds the rest.
#[map]
pub static EXEC_HANDOFF: LruHashMap<u64, ExeIdentityRaw> = LruHashMap::with_max_entries(1024, 0);
/// Where a pass's identity is built (552 bytes: never on the stack).
#[map]
static EXEC_SCRATCH: PerCpuArray<ExeIdentityRaw> = PerCpuArray::with_max_entries(1, 0);

/// `u64` at `src`, 0 when unreadable, without a branch on the result
/// (the helper always writes its destination).
#[inline(always)]
unsafe fn peek_u64(src: *const u8) -> u64 {
    let mut v = core::mem::MaybeUninit::<u64>::uninit();
    let _ = gen::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 8, src as *const c_void);
    v.assume_init()
}

#[inline(always)]
unsafe fn peek_u32(src: *const u8) -> u32 {
    let mut v = core::mem::MaybeUninit::<u32>::uninit();
    let _ = gen::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 4, src as *const c_void);
    v.assume_init()
}

#[lsm(hook = "bprm_check_security")]
pub fn exec_check_lsm(ctx: LsmContext) -> i32 {
    unsafe { try_exec_check_lsm(&ctx) };
    0
}

#[inline(always)]
unsafe fn try_exec_check_lsm(ctx: &LsmContext) {
    // Kernel signature: (bprm).
    let bprm: *const u8 = ctx.arg(0);
    if bprm.is_null() {
        return;
    }
    // Optional offsets, one at a time (5.15 rule 3); userland attaches
    // this program only when all of them resolved.
    let o_file = match off_opt!(LINUX_BINPRM_FILE_OFFSET) {
        Some(o) => o & 0xffff,
        None => return,
    };
    let o_filename = match off_opt!(LINUX_BINPRM_FILENAME_OFFSET) {
        Some(o) => o & 0xffff,
        None => return,
    };
    let o_interp = match off_opt!(LINUX_BINPRM_INTERP_OFFSET) {
        Some(o) => o & 0xffff,
        None => return,
    };
    let s = match EXEC_SCRATCH.get_ptr_mut(0) {
        Some(p) => p,
        None => return,
    };
    let file = peek_u64(bprm.add(o_file)) as *const u8;
    let filename = peek_u64(bprm.add(o_filename)) as *const u8;
    let interp = peek_u64(bprm.add(o_interp)) as *const u8;
    let task = bpf_get_current_task() as *const u8;

    // The file: identity, filesystem, memfd name, link count.
    let inode = peek_u64(file.add(off!(FILE_F_INODE_OFFSET))) as *const u8;
    let sb = peek_u64(inode.add(off!(INODE_I_SB_OFFSET))) as *const u8;
    let s_dev = peek_u32(sb.add(off!(SUPER_BLOCK_S_DEV_OFFSET)));
    let magic = peek_u64(sb.add(off!(SUPER_BLOCK_S_MAGIC_OFFSET)));
    let dentry = peek_u64(file.add(off!(FILE_F_PATH_OFFSET) + off!(PATH_DENTRY_OFFSET))) as *const u8;
    let mut flags = exe_flags::KNOWN;
    if magic == TMPFS_MAGIC || magic == HUGETLBFS_MAGIC || magic == RAMFS_MAGIC {
        flags |= exe_flags::TMPFS;
    }
    let name = peek_u64(dentry.add(off!(DENTRY_D_NAME_OFFSET) + off!(QSTR_NAME_OFFSET))) as *const u8;
    if peek_u64(name) & MEMFD_MASK == MEMFD_PREFIX {
        flags |= exe_flags::MEMFD;
    }
    if let Some(o) = off_opt!(INODE_I_NLINK_OFFSET) {
        if peek_u32(inode.add(o & 0xffff)) == 0 {
            flags |= exe_flags::DELETED;
        }
    }
    // The task's root, where the walk stops.
    let mut task_root: *const u8 = core::ptr::null();
    if let Some(o_fs) = off_opt!(TASK_STRUCT_FS_OFFSET) {
        if let Some(o_root) = off_opt!(FS_STRUCT_ROOT_OFFSET) {
            let fs = peek_u64(task.add(o_fs & 0xffff)) as *const u8;
            task_root = peek_u64(fs.add((o_root & 0xffff) + off!(PATH_DENTRY_OFFSET))) as *const u8;
        }
    }
    let pass: u8 = if interp == filename { 0 } else { 1 };
    (*s).dev = crate::inode_dev::stat_dev(inode, sb, s_dev) as u64;
    (*s).ino = peek_u64(inode.add(off!(INODE_I_INO_OFFSET)));
    (*s).pass = pass;
    (*s)._pad = 0;
    (*s).flags = flags | (nn_exe_walk(dentry as u64, task_root as u64) as u32);

    // One record per pass.
    match crate::exec_check::EXEC_CHECK_EVENTS.reserve::<ExecCheckRaw>(0) {
        Some(mut entry) => {
            let raw: *mut ExecCheckRaw = entry.as_mut_ptr();
            crate::zero::zero(raw);
            let pid_tgid = bpf_get_current_pid_tgid();
            let uid_gid = bpf_get_current_uid_gid();
            (*raw).pid = (pid_tgid >> 32) as u32;
            (*raw).uid = (uid_gid & 0xFFFF_FFFF) as u32;
            (*raw).gid = (uid_gid >> 32) as u32;
            (*raw).timestamp_ns = bpf_ktime_get_ns();
            let parent = peek_u64(task.add(off!(TASK_STRUCT_REAL_PARENT_OFFSET))) as *const u8;
            (*raw).ppid = peek_u32(parent.add(off!(TASK_STRUCT_TGID_OFFSET)));
            if let Ok(comm) = bpf_get_current_comm() {
                let dst = (*raw).comm.as_mut_ptr();
                let mut i = 0usize;
                while i < TASK_COMM_LEN {
                    *dst.add(i) = comm[i];
                    i += 1;
                }
            }
            let _ = gen::bpf_probe_read_kernel_str(
                (*raw).filename.as_mut_ptr() as *mut c_void,
                FILENAME_LEN as u32,
                filename as *const c_void,
            );
            let _ = gen::bpf_probe_read_kernel(
                &mut (*raw).exe as *mut ExeIdentityRaw as *mut c_void,
                core::mem::size_of::<ExeIdentityRaw>() as u32,
                s as *const c_void,
            );
            entry.submit(0);
        }
        None => crate::drops::bump(northnarrow_common::ring_drops::ring_slot::EXEC_CHECK),
    }
    // Pass 0: the file the caller named, for the post-exec record.
    if pass == 0 {
        let _ = EXEC_HANDOFF.insert(&(task as u64), &*s, 0);
    }
}

/// The dentry walk of [`exec_check_lsm`]: writes the path slots, the
/// level count and the root key into the per-CPU scratch, and returns the
/// walk's flags (`TASK_ROOT`, `DEEP`, `UNRESOLVED`).
///
/// A global BPF function (exported, never inlined, integer arguments):
/// the verifier checks its 64-level loop once, on its own
/// (KERNEL_COMPATIBILITY, 5.15 rule 6).
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_exe_walk(dentry: u64, task_root: u64) -> u64 {
    unsafe { exe_walk(dentry as *const u8, task_root as *const u8) }
}

#[inline(always)]
unsafe fn exe_walk(dentry: *const u8, task_root: *const u8) -> u64 {
    let s = match EXEC_SCRATCH.get_ptr_mut(0) {
        Some(p) => p,
        None => return u64::from(exe_flags::UNRESOLVED),
    };
    let o_parent = off!(DENTRY_D_PARENT_OFFSET);
    let o_inode = off!(DENTRY_D_INODE_OFFSET);
    let o_name = off!(DENTRY_D_NAME_OFFSET) + off!(QSTR_NAME_OFFSET);
    let path = (*s).path.as_mut_ptr();
    let mut flags = exe_flags::UNRESOLVED;
    let mut levels: u16 = 0;
    (*s).root_dev = 0;
    (*s).root_ino = 0;
    let mut d = dentry;
    for level in 0..EXE_WALK_DEPTH {
        if d.is_null() {
            break;
        }
        // The task's root is where the task's own view starts: its name
        // is not part of the path.
        if level > 0 && d == task_root {
            flags = exe_flags::TASK_ROOT;
            break;
        }
        let slot = exe_path_slot(level);
        let name = peek_u64(d.add(o_name)) as *const c_void;
        let _ = gen::bpf_probe_read_kernel_str(
            path.add(slot * EXE_PATH_SLOT_LEN) as *mut c_void,
            EXE_PATH_SLOT_LEN as u32,
            name,
        );
        levels = (level + 1) as u16;
        let up = peek_u64(d.add(o_parent)) as *const u8;
        if up == d {
            // The filesystem's root: userland maps its key to a mount point.
            let inode = peek_u64(d.add(o_inode)) as *const u8;
            let sb = peek_u64(inode.add(off!(INODE_I_SB_OFFSET))) as *const u8;
            let s_dev = peek_u32(sb.add(off!(SUPER_BLOCK_S_DEV_OFFSET)));
            (*s).root_dev = crate::inode_dev::stat_dev(inode, sb, s_dev) as u64;
            (*s).root_ino = peek_u64(inode.add(off!(INODE_I_INO_OFFSET)));
            flags = 0;
            break;
        }
        d = up;
    }
    (*s).levels = levels;
    if levels as usize > EXE_PATH_SLOTS {
        flags |= exe_flags::DEEP;
    }
    u64::from(flags)
}
