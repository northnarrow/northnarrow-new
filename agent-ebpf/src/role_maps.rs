//! Lot 2.2 (stage S2): a role is held only with marked executable code, and
//! a protected file is never mapped shared and writable.
//!
//! * **The role marks.** A process holds the agent's or the watchdog's
//!   role only while every executable mapping it makes comes from an image
//!   the agent marked as its own ([`EXEC_MARKS`],
//!   `northnarrow_common::exec_marks::MARK_ROLE`: the two binaries, the
//!   loader and the libraries their processes map, registered by the
//!   agent from an honest start). The two programs here judge, for a
//!   process that holds a role (`PROTECTED_PIDS`' exempt bit) or runs one
//!   of the two binaries (`OWN_EXE_INODES`: a successor before its claim),
//!   each `mmap` with `PROT_EXEC` ([`role_mmap_file`], the kernel's own
//!   mappings at the exec included) and each `mprotect` that asks for
//!   `PROT_EXEC` ([`role_file_mprotect`]; the units refuse it with
//!   `MemoryDenyWriteExecute=`, so the vma's file is not read: any such
//!   request is unmarked). An image without the mark, or anonymous memory,
//!   takes the role away: the process is recorded in [`ROLE_UNMARKED`]
//!   (frozen at its creation: the hooks alone write it), signed
//!   (`FS_OP_ROLE_UNMARKED`), and from then on it is exempt from nothing
//!   (`task_kill::is_exempt_pid`) and never takes a vacant role
//!   (`bpf_defense::fresh_instance_may_load`). The mapping itself goes
//!   through: the refusal is of the role, not of the code.
//! * **Shared writable mappings.** A `MAP_SHARED` mapping of a file opened
//!   for writing (the only mapping `mprotect` can make writable later) of
//!   an inode the agent protects against writes is refused at its `mmap`
//!   (`FS_OP_SHARED_MAP`), to every caller outside the agent's family,
//!   inside a trusted-installer window too: page stores reach the file with
//!   no further hook, so a descriptor kept from a window would keep
//!   writing after it.
//!
//! Nothing is judged before the agent has written the marks
//! ([`EXEC_MARK_ARMED`]): an empty map would take every role away.

use aya_ebpf::{
    cty::{c_int, c_void},
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_probe_read_kernel, generated},
    macros::{lsm, map},
    maps::{Array, HashMap},
    programs::LsmContext,
    EbpfContext,
};
use northnarrow_common::exec_marks::{
    unmarked_for_role, EXEC_MARKS_ARMED_ON, EXEC_MARKS_MAX, ROLE_UNMARKED_MAX,
};
use northnarrow_common::wire::{
    InodeKey, FS_OP_ROLE_UNMARKED, FS_OP_SHARED_MAP, FS_PROTECT_WRITE,
};

use crate::btf_offsets::{FILE_F_INODE_OFFSET, FILE_F_MODE_OFFSET, TASK_STRUCT_START_TIME_OFFSET};

const EPERM: c_int = 1;
/// `PROT_EXEC` (include/uapi/asm-generic/mman-common.h).
const PROT_EXEC: u64 = 0x4;
/// `MAP_TYPE`, `MAP_SHARED`, `MAP_SHARED_VALIDATE`.
const MAP_TYPE: u64 = 0x0f;
const MAP_SHARED: u64 = 0x01;
const MAP_SHARED_VALIDATE: u64 = 0x03;
/// `FMODE_WRITE` (include/linux/fs.h).
const FMODE_WRITE: u32 = 0x2;

/// `(dev, ino)` of an executable image → its marks
/// (`northnarrow_common::exec_marks`). Written by the agent; pinned by
/// name, so a successor's mappings are judged against the marks its
/// predecessor wrote.
#[map]
pub static EXEC_MARKS: HashMap<InodeKey, u32> = HashMap::pinned(EXEC_MARKS_MAX, 0);

/// Slot 0: `EXEC_MARKS_ARMED_ON` once the agent wrote the marks.
#[map]
pub static EXEC_MARK_ARMED: Array<u32> = Array::pinned(1, 0);

/// tgid → its start (`task_struct.start_time`): the processes that lost
/// their role. Frozen by the agent at its creation (`BPF_MAP_FREEZE`): only
/// these programs write it, and `role_exit` removes an entry at the
/// process's exit.
#[map]
pub static ROLE_UNMARKED: HashMap<u32, u64> = HashMap::pinned(ROLE_UNMARKED_MAX, 0);

/// `tgid` lost its role (an unmarked executable mapping).
#[inline(always)]
pub fn role_lost(tgid: u32) -> bool {
    // SAFETY: a lookup in this program's own map; nothing is kept.
    unsafe { ROLE_UNMARKED.get(&tgid).is_some() }
}

/// [`role_lost`] as a global BPF function (scalar argument, never inlined):
/// the hooks that ask it many times (an exemption, a fresh instance) keep
/// its key off their own stack frames.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn nn_role_lost(tgid: u64) -> u64 {
    u64::from(role_lost(tgid as u32))
}

/// The process `tgid` exited: its entry goes (a reused tgid is another
/// process).
#[inline(always)]
pub fn forget(tgid: u32) {
    let _ = ROLE_UNMARKED.remove(&tgid);
}

#[inline(always)]
fn armed() -> bool {
    matches!(EXEC_MARK_ARMED.get(0), Some(v) if *v == EXEC_MARKS_ARMED_ON)
}

/// Argument `i` of the hook as a scalar (no BTF typing: the file goes to a
/// global function, which takes scalars only).
#[inline(always)]
unsafe fn raw_arg(ctx: &LsmContext, i: usize) -> u64 {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let args = ctx.as_ptr() as *const u64;
        let mut v = 0u64;
        let _ = generated::bpf_probe_read_kernel(&mut v as *mut u64 as *mut c_void, 8, args.add(i) as *const c_void);
        v
    }
}

/// `mmap_file(struct file *file, unsigned long reqprot, unsigned long prot,
/// unsigned long flags)` (5.15 to 7.0).
#[lsm(hook = "mmap_file")]
pub fn role_mmap_file(ctx: LsmContext) -> i32 {
    unsafe { try_role_mmap_file(&ctx) }
}

#[inline(always)]
unsafe fn try_role_mmap_file(ctx: &LsmContext) -> i32 {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let file = raw_arg(ctx, 0);
        let flags = raw_arg(ctx, 3);
        if file != 0 && matches!(flags & MAP_TYPE, MAP_SHARED | MAP_SHARED_VALIDATE) && nn_shared_map_refused(file) == 1 {
            return -EPERM;
        }
        // what the caller asked, or what the kernel made of it
        // (`READ_IMPLIES_EXEC`)
        if (raw_arg(ctx, 1) | raw_arg(ctx, 2)) & PROT_EXEC != 0 {
            let _ = nn_role_map(file);
        }
        0
    }
}

/// `file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
/// unsigned long prot)`: an executable request in a role process takes the
/// role away whatever the vma maps (see the module's doc).
#[lsm(hook = "file_mprotect")]
pub fn role_file_mprotect(ctx: LsmContext) -> i32 {
    unsafe {
        if (raw_arg(&ctx, 1) | raw_arg(&ctx, 2)) & PROT_EXEC != 0 {
            let _ = nn_role_map(0);
        }
    }
    0
}

/// Whether a shared mapping of `file` (a scalar pointer) is refused: the
/// file was opened for writing, its inode is protected against writes, and
/// the caller is outside the agent's family — inside a window too. 1 when
/// refused (signed), 0 otherwise; an unreadable file or inode is a
/// fail-open, counted. A global BPF function: verified once.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn nn_shared_map_refused(file: u64) -> u64 {
    // SAFETY: the file and its inode are read through the helper only.
    unsafe {
        let file = file as *const u8;
        if file.is_null() {
            return 0;
        }
        let fmode = match bpf_probe_read_kernel::<u32>(file.add(off!(FILE_F_MODE_OFFSET)) as *const u32) {
            Ok(m) => m,
            Err(_) => {
                crate::fail_open::bump(northnarrow_common::fail_open::hook::FILE_PERMISSION);
                return 0;
            }
        };
        if fmode & FMODE_WRITE == 0 {
            return 0;
        }
        let inode = match bpf_probe_read_kernel::<*const c_void>(file.add(off!(FILE_F_INODE_OFFSET)) as *const *const c_void) {
            Ok(p) if !p.is_null() => p,
            _ => {
                crate::fail_open::bump(northnarrow_common::fail_open::hook::FILE_PERMISSION);
                return 0;
            }
        };
        let Some(key) = crate::inode_protect::read_inode_key(inode) else {
            crate::fail_open::bump(northnarrow_common::fail_open::hook::FILE_PERMISSION);
            return 0;
        };
        let protected = match crate::inode_protect::PROTECTED_INODES.get(&key) {
            Some(f) => *f & FS_PROTECT_WRITE != 0,
            None => false,
        };
        if !protected {
            return 0;
        }
        let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
        if crate::task_kill::is_exempt_pid(tgid) {
            return 0;
        }
        crate::inode_protect::emit_attempt(FS_OP_SHARED_MAP, key);
        1
    }
}

/// An executable mapping of `file` (0: anonymous memory, or an `mprotect`
/// whose vma is not read) by the calling process: when the process holds a
/// role or runs one of the two binaries and the image has no role mark, the
/// process loses its role ([`ROLE_UNMARKED`]), signed once. Always 0 (the
/// mapping goes through). A global BPF function: verified once.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn nn_role_map(file: u64) -> u64 {
    // SAFETY: the task, the file and its inode are read through the helper
    // only; the maps are this program's.
    unsafe {
        if !armed() {
            return 0;
        }
        let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
        if role_lost(tgid) {
            return 0;
        }
        let task = bpf_get_current_task() as *const u8;
        if task.is_null() {
            return 0;
        }
        // its role lost was ruled out above: exempt is holding a role
        let holds = crate::task_kill::is_exempt_pid(tgid);
        if !holds && !crate::bpf_defense::task_runs_own_binary(task) {
            return 0;
        }
        // anonymous memory, or a file whose inode cannot be read: no mark
        // (fail closed for the role, never for the mapping)
        let mut key = InodeKey { dev: 0, ino: 0 };
        let mut marks: Option<u32> = None;
        if file != 0 {
            if let Ok(inode) = bpf_probe_read_kernel::<*const c_void>(
                (file as *const u8).add(off!(FILE_F_INODE_OFFSET)) as *const *const c_void,
            ) {
                if !inode.is_null() {
                    if let Some(k) = crate::inode_protect::read_inode_key(inode) {
                        key = k;
                        marks = EXEC_MARKS.get(&k).copied();
                    }
                }
            }
        }
        if !unmarked_for_role(marks) {
            return 0;
        }
        let start = bpf_probe_read_kernel::<u64>(task.add(off!(TASK_STRUCT_START_TIME_OFFSET)) as *const u64).unwrap_or(0);
        // a full map cannot record it: the record still says so (the
        // process keeps what it holds — the failure is the map's, signed)
        let _ = ROLE_UNMARKED.insert(&tgid, &start, 0);
        crate::inode_protect::emit_attempt(FS_OP_ROLE_UNMARKED, key);
        0
    }
}
