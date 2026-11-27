//! Lot 2.2 (stage S2): a role is held only with marked executable code, and
//! a protected file is never mapped shared and writable.
//!
//! * **The role marks.** A process holds the agent's or the watchdog's
//!   role only while its MAIN image is an inode the agent marked as a role
//!   binary ([`EXEC_MARKS`], `northnarrow_common::exec_marks::MARK_ROLE`:
//!   the two binaries the install or the upgrade put in place, inside a
//!   window) and every other executable mapping it makes is trusted code
//!   WHEN IT IS MADE (the review of #644, decision D10): its file passes
//!   the window's exec rule's test (`exec_marks::code_verdict`: a regular
//!   file owned by root of the initial user namespace, writable by
//!   neither its group nor others, with a name, on a local filesystem of
//!   the initial user namespace, through a mount that is not idmapped).
//!   The two programs here judge, for a process that holds a role
//!   (`PROTECTED_PIDS`' exempt bit) or runs one of the two binaries
//!   (`OWN_EXE_INODES`: a successor before its claim), each `mmap` with
//!   `PROT_EXEC` ([`role_mmap_file`], the kernel's own mappings at the exec
//!   included) and each `mprotect` that ADDS `PROT_EXEC` to a mapping
//!   ([`role_file_mprotect`]: its vma's file, judged the same way; one
//!   already executable was judged at its `mmap`). Nothing is judged again
//!   later: a library deleted after it was mapped (the old C library after
//!   an upgrade without a reboot) was trusted when it was mapped and stays
//!   so; a new C library, loader or NSS module mapped after an upgrade, or
//!   opened with `dlopen` after the start, is judged on its own file. A
//!   main image without the mark, anonymous memory, or a file that fails
//!   the test takes the role away: the process is recorded in
//!   [`ROLE_UNMARKED`] (frozen at its creation: the hooks alone write it),
//!   signed (`FS_OP_ROLE_UNMARKED`), and from then on it is exempt from
//!   nothing (`task_kill::is_exempt_pid`) and never takes a vacant role
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
//! ([`EXEC_MARK_ARMED`]): an empty map would take every role away; a
//! write of the marks that fails clears the flag again (the agent's half).

use aya_ebpf::{
    cty::{c_int, c_void},
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_probe_read_kernel, generated},
    macros::{lsm, map},
    maps::{Array, HashMap},
    programs::LsmContext,
    EbpfContext,
};
use northnarrow_common::exec_marks::{
    role_mapping_verdict, unmarked_for_role, CodeFacts, CODE_TRUSTED, EXEC_MARKS_ARMED_ON, EXEC_MARKS_MAX,
    ROLE_UNMARKED_MAX,
};
use northnarrow_common::wire::{
    InodeKey, FS_OP_ROLE_UNMARKED, FS_OP_SHARED_MAP, FS_PROTECT_WRITE,
};

use crate::btf_offsets::{
    FILE_F_INODE_OFFSET, FILE_F_MODE_OFFSET, FILE_F_PATH_OFFSET, INODE_I_MODE_OFFSET, INODE_I_NLINK_OFFSET,
    INODE_I_SB_OFFSET, INODE_I_UID_OFFSET, MNT_IDMAP_OWNER_OFFSET, MNT_IDMAP_UID_NR_EXTENTS_OFFSET, PATH_MNT_OFFSET,
    SUPER_BLOCK_S_MAGIC_OFFSET, SUPER_BLOCK_S_USER_NS_OFFSET, TASK_STRUCT_START_TIME_OFFSET,
    USER_NAMESPACE_LEVEL_OFFSET, VFSMOUNT_MNT_IDMAP_OFFSET, VFSMOUNT_MNT_USERNS_OFFSET, VM_AREA_STRUCT_VM_FILE_OFFSET,
    VM_AREA_STRUCT_VM_FLAGS_OFFSET,
};

const EPERM: c_int = 1;
/// `PROT_EXEC` (include/uapi/asm-generic/mman-common.h).
const PROT_EXEC: u64 = 0x4;
/// `MAP_TYPE`, `MAP_SHARED`, `MAP_SHARED_VALIDATE`.
const MAP_TYPE: u64 = 0x0f;
const MAP_SHARED: u64 = 0x01;
const MAP_SHARED_VALIDATE: u64 = 0x03;
/// `FMODE_WRITE` (include/linux/fs.h).
const FMODE_WRITE: u32 = 0x2;
/// `VM_EXEC` (include/linux/mm.h).
const VM_EXEC: u64 = 0x4;

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

/// `tgid` lost its role (a main image without the mark, or an executable
/// mapping that was not trusted code).
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
            let _ = nn_role_map(file, 0);
        }
        0
    }
}

/// `file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
/// unsigned long prot)`: an `mprotect` that asks for `PROT_EXEC`, judged
/// on the vma (see [`nn_role_map`]).
#[lsm(hook = "file_mprotect")]
pub fn role_file_mprotect(ctx: LsmContext) -> i32 {
    unsafe {
        if (raw_arg(&ctx, 1) | raw_arg(&ctx, 2)) & PROT_EXEC != 0 {
            let vma = raw_arg(&ctx, 0);
            if vma != 0 {
                let _ = nn_role_map(0, vma);
            }
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

/// An executable mapping by the calling process — of `file` (0: anonymous
/// memory) at an `mmap`, or of `vma`'s file at an `mprotect` (`vma` not 0):
/// when the process holds a role or runs one of the two binaries, the
/// mapping is judged (`exec_marks::role_mapping_verdict`: the main image
/// marked, the mapped file marked or trusted code); an `mprotect` of a
/// mapping already executable is not (it was judged at its `mmap`). A
/// verdict other than trusted takes the role away ([`ROLE_UNMARKED`]),
/// signed once. Always 0 (the mapping goes through). A global BPF
/// function: verified once.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn nn_role_map(file: u64, vma: u64) -> u64 {
    // SAFETY: the task, the vma, the file and what they point to are read
    // through the helper only; the maps are this program's.
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
        let mut file = file;
        if vma != 0 {
            let (Some(o_flags), Some(o_file)) =
                (off_opt!(VM_AREA_STRUCT_VM_FLAGS_OFFSET), off_opt!(VM_AREA_STRUCT_VM_FILE_OFFSET))
            else {
                crate::fail_open::bump(northnarrow_common::fail_open::hook::FILE_PERMISSION);
                return 0;
            };
            let Ok(flags) = bpf_probe_read_kernel::<u64>((vma as *const u8).add(o_flags) as *const u64) else {
                crate::fail_open::bump(northnarrow_common::fail_open::hook::FILE_PERMISSION);
                return 0;
            };
            if flags & VM_EXEC != 0 {
                return 0;
            }
            file = bpf_probe_read_kernel::<u64>((vma as *const u8).add(o_file) as *const u64).unwrap_or(0);
        }
        let main_marks = match crate::bpf_defense::task_exe_key(task) {
            Some(k) => EXEC_MARKS.get(&k).copied(),
            None => None,
        };
        // anonymous memory, or a file whose inode cannot be read: no file
        // judged (fail closed for the role, never for the mapping)
        let mut key = InodeKey { dev: 0, ino: 0 };
        let mut file_marks: Option<u32> = None;
        let mut facts: Option<CodeFacts> = None;
        if file != 0 {
            if let Ok(inode) = bpf_probe_read_kernel::<*const c_void>(
                (file as *const u8).add(off!(FILE_F_INODE_OFFSET)) as *const *const c_void,
            ) {
                if !inode.is_null() {
                    if let Some(k) = crate::inode_protect::read_inode_key(inode) {
                        key = k;
                        file_marks = EXEC_MARKS.get(&k).copied();
                    }
                    if unmarked_for_role(file_marks) {
                        facts = code_facts(file as *const u8, inode as *const u8);
                    }
                }
            }
        }
        if role_mapping_verdict(main_marks, file_marks, facts) == CODE_TRUSTED {
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

/// What the trust test reads of a mapping's `file` and its `inode`
/// (`exec_marks::CodeFacts`); `None` when its mode or owner cannot be read
/// (no file judged). A field this kernel does not have is read as passing
/// (`i_nlink`, the superblock's user namespace, the mount's idmapping:
/// before 5.12 no mount is idmapped), counted as a fail-open.
#[inline(always)]
unsafe fn code_facts(file: *const u8, inode: *const u8) -> Option<CodeFacts> {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let mode = bpf_probe_read_kernel::<u16>(inode.add(off!(INODE_I_MODE_OFFSET)) as *const u16).ok()?;
        let uid = bpf_probe_read_kernel::<u32>(inode.add(off!(INODE_I_UID_OFFSET)) as *const u32).ok()?;
        let nlink = match off_opt!(INODE_I_NLINK_OFFSET) {
            Some(o) => bpf_probe_read_kernel::<u32>(inode.add(o) as *const u32).ok(),
            None => None,
        };
        let sb = bpf_probe_read_kernel::<*const u8>(inode.add(off!(INODE_I_SB_OFFSET)) as *const *const u8).unwrap_or(core::ptr::null());
        let (magic, virtiofs, foreign_sb) = if sb.is_null() {
            crate::fail_open::bump(northnarrow_common::fail_open::hook::FILE_PERMISSION);
            (0, false, false)
        } else {
            let magic = bpf_probe_read_kernel::<u64>(sb.add(off!(SUPER_BLOCK_S_MAGIC_OFFSET)) as *const u64).unwrap_or(0);
            let virtiofs = magic == northnarrow_common::exec_marks::FUSE_SUPER_MAGIC && crate::execq::fs_type_is_virtiofs(sb);
            let foreign = match off_opt!(SUPER_BLOCK_S_USER_NS_OFFSET) {
                Some(o) => userns_level(bpf_probe_read_kernel::<*const u8>(sb.add(o) as *const *const u8).unwrap_or(core::ptr::null())) != 0,
                None => false,
            };
            (magic, virtiofs, foreign)
        };
        Some(CodeFacts {
            mode: u32::from(mode),
            uid,
            nlink,
            magic,
            virtiofs,
            foreign_sb,
            idmapped: mount_idmapped(file),
        })
    }
}

/// The `level` of user namespace `ns` (0: the initial one); 0 when it
/// cannot be read (counted).
#[inline(always)]
unsafe fn userns_level(ns: *const u8) -> u32 {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let Some(o) = off_opt!(USER_NAMESPACE_LEVEL_OFFSET) else {
            return 0;
        };
        if ns.is_null() {
            crate::fail_open::bump(northnarrow_common::fail_open::hook::FILE_PERMISSION);
            return 0;
        }
        bpf_probe_read_kernel::<u32>(ns.add(o) as *const u32).unwrap_or(0)
    }
}

/// Whether `file` was opened through an idmapped mount: the mount's
/// `mnt_userns` other than the initial user namespace (5.12 to 6.2), or its
/// `mnt_idmap` with maps of its own (from 6.7) or of a user namespace other
/// than the initial one (6.3 to 6.6). A kernel with neither field has no
/// idmapped mount (before 5.12); one whose idmapping has neither known
/// layout is read as not idmapped, counted.
#[inline(always)]
unsafe fn mount_idmapped(file: *const u8) -> bool {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let o_userns = off_opt!(VFSMOUNT_MNT_USERNS_OFFSET);
        let o_map = off_opt!(VFSMOUNT_MNT_IDMAP_OFFSET);
        if o_userns.is_none() && o_map.is_none() {
            return false;
        }
        let mnt = bpf_probe_read_kernel::<*const u8>(
            file.add(off!(FILE_F_PATH_OFFSET) + off!(PATH_MNT_OFFSET)) as *const *const u8,
        )
        .unwrap_or(core::ptr::null());
        if mnt.is_null() {
            crate::fail_open::bump(northnarrow_common::fail_open::hook::FILE_PERMISSION);
            return false;
        }
        if let Some(o) = o_userns {
            let ns = bpf_probe_read_kernel::<*const u8>(mnt.add(o) as *const *const u8).unwrap_or(core::ptr::null());
            return userns_level(ns) != 0;
        }
        let Some(o_map) = o_map else {
            return false;
        };
        let map = bpf_probe_read_kernel::<*const u8>(mnt.add(o_map) as *const *const u8).unwrap_or(core::ptr::null());
        if map.is_null() {
            return false;
        }
        if let Some(o) = off_opt!(MNT_IDMAP_UID_NR_EXTENTS_OFFSET) {
            return bpf_probe_read_kernel::<u32>(map.add(o) as *const u32).unwrap_or(0) != 0;
        }
        match off_opt!(MNT_IDMAP_OWNER_OFFSET) {
            Some(o) => {
                userns_level(bpf_probe_read_kernel::<*const u8>(map.add(o) as *const *const u8).unwrap_or(core::ptr::null()))
                    != 0
            }
            None => {
                crate::fail_open::bump(northnarrow_common::fail_open::hook::FILE_PERMISSION);
                false
            }
        }
    }
}
