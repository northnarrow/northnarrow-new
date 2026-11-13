//! Lab PR 223 (EXPERIMENTAL) — exec quarantine at first sight, the
//! kernel half (design `docs/design/EXEC_QUARANTINE.md`, wire
//! `northnarrow_common::wire::execq`).
//!
//! Two calls, both in the exec'ing task:
//!
//! - [`note_pass`], from `exec_check_lsm` (LSM `bprm_check_security`), for
//!   each binfmt pass after the dentry walk: a file in a guarded class
//!   whose `(dev, ino)` is not in [`EXECQ_KNOWN`] under the same ctime and
//!   size becomes the exec's candidate in [`EXECQ_CAND`].
//! - [`maybe_stop`], from `sched_process_exec`, once the exec has passed
//!   its point of no return (the new image is installed, `de_thread` left
//!   one thread) and before the task returns to user mode: the candidate
//!   is reported on [`EXECQ_EVENTS`] and, in enforce mode, the task is sent
//!   `SIGSTOP` with `bpf_send_signal`. The signal is pending when the
//!   tracepoint returns (the program runs with interrupts enabled, so the
//!   helper queues it at once, not through irq_work), and the exit to user
//!   mode delivers it before the first instruction of the new image — the
//!   dynamic loader's, or a static binary's entry point.
//!
//! Fail-open by construction: no heartbeat from the agent within
//! `HEARTBEAT_MAX_NS`, a full ring or a refused signal leave the process
//! running (each counted in [`EXECQ_COUNTERS`]). The agent's own processes
//! (`PROTECTED_PIDS`) are never stopped.
use aya_ebpf::{
    cty::c_void,
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns, generated},
    macros::{lsm, map},
    maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::LsmContext,
};
use northnarrow_common::wire::exe::{
    exe_flags, exe_path_slot, ExeIdentityRaw, TaskKey, EXE_PATH_SLOT_LEN, EXE_WALK_DEPTH,
};
use northnarrow_common::wire::execq::{
    class, conf_slot, counter, mode, root_kind, stop_flags, ExecqCandRaw, ExecqKey, ExecqKnown,
    ExecqStopRaw, ExecqStopped,
};

use crate::btf_offsets::{
    DENTRY_D_INODE_OFFSET, DENTRY_D_PARENT_OFFSET, FILE_F_INODE_OFFSET, INODE_I_CTIME_NSEC_OFFSET,
    INODE_I_CTIME_SEC_OFFSET, INODE_I_INO_OFFSET, INODE_I_MODE_OFFSET, INODE_I_SB_OFFSET,
    FILE_SYSTEM_TYPE_NAME_OFFSET, INODE_I_SIZE_OFFSET, INODE_I_UID_OFFSET, SUPER_BLOCK_S_DEV_OFFSET,
    SUPER_BLOCK_S_MAGIC_OFFSET, SUPER_BLOCK_S_TYPE_OFFSET,
    TASK_STRUCT_REAL_PARENT_OFFSET, TASK_STRUCT_START_TIME_OFFSET, TASK_STRUCT_TGID_OFFSET,
};

/// `SIGSTOP` on every Linux architecture the agent supports.
const SIGSTOP: u32 = 19;
/// `EACCES`.
const EACCES: i32 = 13;
/// `S_IWOTH`.
const S_IWOTH: u16 = 0o002;

/// Mode, guarded classes, heartbeat bound — written once by the agent
/// before the exec programs attach, then frozen.
#[map]
pub static EXECQ_CONF: Array<u64> = Array::with_max_entries(conf_slot::SLOTS, 0);
/// Slot 0: the agent's last heartbeat (CLOCK_MONOTONIC ns).
#[map]
pub static EXECQ_ALIVE: Array<u64> = Array::with_max_entries(1, 0);
/// Identities already judged, with the content stamp they were judged
/// under. Written by the agent; per boot of the agent (not pinned).
#[map]
pub static EXECQ_KNOWN: LruHashMap<ExecqKey, ExecqKnown> = LruHashMap::with_max_entries(16384, 0);
/// Roots of the guarded mounts (a separate `/home`, `/tmp`…), keyed like
/// `ExeIdentityRaw::root_dev/root_ino` (`stat()`'s device and inode of the
/// mount point). Written by the agent. Lot 318 (BUG108's mini-hunt): 1024
/// entries — it had 64, and a user's FUSE mounts under their home (each a
/// guarded root) filled them: the agent's inserts past the 64th failed
/// unseen and those mounts had no class. FUSE's own limit (`mount_max`)
/// is 1000.
#[map]
pub static EXECQ_ROOTS: HashMap<ExecqKey, u32> = HashMap::with_max_entries(EXECQ_ROOTS_CAPACITY, 0);

/// [`EXECQ_ROOTS`]' capacity.
pub const EXECQ_ROOTS_CAPACITY: u32 = 1024;
/// The candidate of each exec in progress, keyed by `task_struct`, from the
/// exec's pass to its `sched_process_exec`. Lot 325 (the re-check of #546,
/// R6): a plain hash, never an LRU — the interpreter's pass and
/// [`refuse_script`] hold a pointer to the entry in a preemptible LSM
/// program, and an LRU insert elsewhere that found its CPU's free list
/// empty could evict the entry and hand its memory to another task's
/// candidate (5.15/6.8 with `preempt=full` and more than 8 CPUs). An entry
/// is removed at `sched_process_exec`, at the task's next exec, at a
/// refused pass, and when the task is freed (`task_free`,
/// `crate::task_scratch::nn_task_free`: a failed exec's candidate was left
/// to the LRU). Past [`EXECQ_CAND_CAP`] in flight, a candidate is dropped
/// (counted, `CAND_DROPPED`): the exec runs, unheld.
#[map]
static EXECQ_CAND: HashMap<u64, ExecqCandRaw> = HashMap::with_max_entries(EXECQ_CAND_CAP, 0);
/// [`EXECQ_CAND`]'s room: the execs between their pass and their
/// `sched_process_exec`.
pub(crate) const EXECQ_CAND_CAP: u32 = 4096;
/// The review of #547 (F4): one uid's share of [`EXECQ_CAND`] — one user's
/// threads, each held in an exec (a FUSE-backed binary it never answers),
/// cannot take the room every other user's execs need.
pub(crate) const EXECQ_CAND_PER_UID: u64 = 1024;
/// The candidates each uid holds ([`EXECQ_CAND_PER_UID`]).
#[map]
static EXECQ_CAND_UIDS: HashMap<u32, u64> = HashMap::with_max_entries(4096, 0);
/// Where a candidate is built (584 bytes: never on the stack): the running
/// task's own entry, made, copied into [`EXECQ_CAND`] and removed in one
/// run. Lot 322: it was a per-CPU buffer in a program that runs
/// preemptible; built in place in the LRU it could be evicted under the
/// writer (the review of #546, F4).
#[map]
static EXECQ_CAND_SCRATCH: HashMap<TaskKey, ExecqCandRaw> =
    HashMap::with_max_entries(crate::task_scratch::TASK_SCRATCH_CAP, 0);
/// Processes stopped and not decided yet (tgid → start, stop time). Pinned:
/// a restarted agent resumes what its predecessor left stopped.
#[map]
pub static EXECQ_STOPPED: HashMap<u32, ExecqStopped> = HashMap::pinned(4096, 0);
/// One record per candidate exec. 256 KiB: about 400 records of 640 bytes.
#[map]
pub static EXECQ_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);
/// Per-CPU counters (`counter::*`).
#[map]
pub static EXECQ_COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(counter::SLOTS, 0);

#[inline(always)]
fn bump(slot: u32) {
    if let Some(c) = EXECQ_COUNTERS.get_ptr_mut(slot) {
        // SAFETY: per-CPU slot, bounded by the map size.
        unsafe { *c = (*c).wrapping_add(1) };
    }
}

#[inline(always)]
fn conf(slot: u32) -> u64 {
    match EXECQ_CONF.get(slot) {
        Some(v) => *v,
        None => 0,
    }
}

/// The guard is on (observe or enforce).
#[inline(always)]
pub(crate) fn armed() -> bool {
    conf(conf_slot::MODE) != mode::OFF
}


#[inline(always)]
unsafe fn peek_u64(src: *const u8) -> u64 {
    let mut v = core::mem::MaybeUninit::<u64>::uninit();
    let _ = generated::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 8, src as *const c_void);
    v.assume_init()
}

#[inline(always)]
unsafe fn peek_u32(src: *const u8) -> u32 {
    let mut v = core::mem::MaybeUninit::<u32>::uninit();
    let _ = generated::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 4, src as *const c_void);
    v.assume_init()
}

#[inline(always)]
unsafe fn peek_u16(src: *const u8) -> u16 {
    let mut v = core::mem::MaybeUninit::<u16>::uninit();
    let _ = generated::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 2, src as *const c_void);
    v.assume_init()
}

/// "tmp", "var", "home", "root", "dev", "shm" as the low bytes of a
/// little-endian u64, their NUL included (a slot holds the name the kernel
/// read and its NUL).
const NAME_TMP: u64 = 0x0070_6d74;
const NAME_VAR: u64 = 0x0072_6176;
const NAME_DEV: u64 = 0x0076_6564;
const NAME_SHM: u64 = 0x006d_6873;
const NAME_HOME: u64 = 0x00_656d_6f68;
const NAME_ROOT: u64 = 0x00_746f_6f72;
const MASK4: u64 = 0xffff_ffff;
const MASK5: u64 = 0xff_ffff_ffff;

/// First 8 bytes of path level `level`'s slot in the walk's scratch.
#[inline(always)]
unsafe fn level_name(s: *const ExeIdentityRaw, level: usize) -> u64 {
    let slot = exe_path_slot(level & 63) & 15;
    peek_u64((*s).path.as_ptr().add(slot * EXE_PATH_SLOT_LEN))
}

/// The guarded classes of the file the walk just described (the task's
/// scratch entry of `exec_lsm`, `tid` and `start`). A global function
/// (integer arguments, never inlined): the verifier checks it once, apart
/// from the LSM program.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_execq_classify(dentry: u64, flags: u64, tid: u64, start: u64) -> u64 {
    unsafe {
        match crate::exec_lsm::EXEC_SCRATCH.get_ptr(&crate::task_scratch::key(tid, start)) {
            Some(s) => classify(s, dentry as *const u8, flags as u32) as u64,
            // Lot 322: the task's walk gone (the LRU's eviction under a
            // flood of execs in flight): a file the walk cannot place, as
            // an unresolved walk is.
            None => u64::from(class::TMP | class::VAR_TMP | class::HOME),
        }
    }
}

/// The classes of the file whose walk is in `s` (the exec sensor's scratch,
/// or the mapping check's, `crate::execpol`).
#[inline(always)]
pub(crate) unsafe fn classify(s: *const ExeIdentityRaw, dentry: *const u8, flags: u32) -> u32 {
    let mut c = 0u32;
    if flags & exe_flags::MEMFD != 0 {
        c |= class::MEMFD;
    }
    if flags & exe_flags::DELETED != 0 {
        c |= class::DELETED;
    }
    if flags & exe_flags::TMPFS != 0 {
        c |= class::TMPFS;
    }
    // The directory the file is in: writable by every user?
    let parent = peek_u64(dentry.add(off!(DENTRY_D_PARENT_OFFSET))) as *const u8;
    if !parent.is_null() && parent != dentry {
        let pinode = peek_u64(parent.add(off!(DENTRY_D_INODE_OFFSET))) as *const u8;
        if !pinode.is_null() && peek_u16(pinode.add(off!(INODE_I_MODE_OFFSET))) & S_IWOTH != 0 {
            c |= class::WORLD_WRITABLE_DIR;
        }
    }
    if flags & exe_flags::UNRESOLVED != 0 {
        // Lot 318 (external bug hunt BUG108's variant): no root within the
        // walk's 64 levels — a path no installed program has, and one any
        // user can make where they write (`mkdir` 65 times, by relative
        // paths). It had no path class at all, so a binary placed that deep
        // in a home or under /tmp was neither held nor judged by a cell.
        // Classed where it most likely is, a user-writable place: tmp,
        // var_tmp and home (other_home by its owner, below).
        c |= class::TMP | class::VAR_TMP | class::HOME;
    } else if flags & exe_flags::TASK_ROOT != 0 {
        // Levels 0..levels-1 are the names below the task's root: the top
        // one is the first directory of the task's own view.
        let levels = (*s).levels as usize;
        if levels >= 2 && levels <= 64 {
            let top = level_name(s, levels - 1);
            if top & MASK4 == NAME_TMP {
                c |= class::TMP;
            } else if top & MASK5 == NAME_HOME || top & MASK5 == NAME_ROOT {
                c |= class::HOME;
            } else if levels >= 3 {
                let next = level_name(s, levels - 2) & MASK4;
                if top & MASK4 == NAME_VAR && next == NAME_TMP {
                    c |= class::VAR_TMP;
                } else if top & MASK4 == NAME_DEV && next == NAME_SHM {
                    c |= class::DEV_SHM;
                }
            }
        }
    }
    // A guarded mount, and which point it is mounted at (lab PR 226).
    // Lot 318 (external bug hunt BUG108): by the identity of an ancestor —
    // the root of the mount at the guarded point — wherever the walk ended.
    // It was the walk's end only, the root of the superblock: a btrfs
    // subvolume mounted at `/home` (Fedora's and openSUSE's layout) ends on
    // the top-level subvolume, a directory bound at `/home` on its own
    // filesystem's root, and neither is the key the agent publishes. In a
    // task's own view (a chroot, a container) it adds to the classes of the
    // names.
    // The re-check of #545 (R3): not past the task's own root — a
    // container's or a chroot's root on a directory of the host (an
    // unprivileged LXC container's `rootfs`, rootless podman's vfs or btrfs
    // storage, both in a home) took the host's `home` from above it, and
    // every program of the container's image (owned by its root, a host
    // subuid) was `other_home`. As before lot 318 there: the task's view.
    let task_root =
        crate::exec_lsm::task_root_of(aya_ebpf::helpers::bpf_get_current_task() as *const u8);
    let g = nn_guarded_root(dentry as u64, task_root as u64);
    // Lot 318 (the review of #538, F1 and F3: N8's kernel half): a file of
    // a FUSE filesystem outside the task's own root is guarded whatever the
    // roots say. Its daemon answers every GETATTR, the root's included, and
    // the kernel takes the inode number it gives (`fuse_change_attributes`):
    // a user's daemon made its root's key one the agent never published
    // (the review saw the root's 1 become 7 on 6.18), and a user's FUSE
    // mounts past `EXECQ_ROOTS`' room had none. Where no published root
    // places it, it is classed where a user writes, as a walk that finds no
    // root is. Inside the task's root (a virtiofs root filesystem) the names
    // decide, as for any other.
    // The agent publishes a FUSE mount by its device alone, `(s_dev,
    // FUSE_BY_DEVICE)` (lot 311b; it never `stat`s a FUSE root): found, its
    // point's kind applies.
    let mut g = g;
    let fuse = if flags & exe_flags::TASK_ROOT == 0 {
        fuse_dev(dentry)
    } else {
        0
    };
    if fuse != 0 {
        c |= class::GUARDED_MOUNT;
        let key = ExecqKey {
            dev: fuse & FUSE_DEV_MASK,
            ino: FUSE_BY_DEVICE,
        };
        if let Some(v) = EXECQ_ROOTS.get(&key) {
            g = GUARDED_ROOT_FOUND | u64::from(*v);
        } else if g & GUARDED_ROOT_FOUND == 0 {
            c |= class::TMP | class::VAR_TMP | class::HOME;
        }
    }
    if g & GUARDED_ROOT_FOUND != 0 {
        let v = g as u32;
        // a guarded mount's root; a guarded point's own identity (lot 318,
        // the review of #545, F2: `/var/tmp` in openSUSE's `@/var`, `/home`
        // under ostree's `/var` bind) gives its path class only
        if v & root_kind::GUARDED != 0 {
            c |= class::GUARDED_MOUNT;
        }
        if v & root_kind::TMP != 0 {
            c |= class::TMP;
        }
        if v & root_kind::VAR_TMP != 0 {
            c |= class::VAR_TMP;
        }
        if v & root_kind::DEV_SHM != 0 {
            c |= class::DEV_SHM;
        }
        if v & root_kind::HOME != 0 {
            c |= class::HOME;
        }
    }
    // Lab PR 226: a home file another account owns (neither the caller's
    // real uid nor root).
    if c & class::HOME != 0 {
        if let Some(o) = off_opt!(INODE_I_UID_OFFSET) {
            let inode = peek_u64(dentry.add(off!(DENTRY_D_INODE_OFFSET))) as *const u8;
            if !inode.is_null() {
                let owner = peek_u32(inode.add(o & 0xffff));
                let caller = bpf_get_current_uid_gid() as u32;
                if owner != 0 && owner != caller {
                    c |= class::OTHER_HOME;
                }
            }
        }
    }
    c
}

/// `FUSE_SUPER_MAGIC` (include/uapi/linux/magic.h): `fuse`, `fuseblk`,
/// `virtiofs`.
const FUSE_SUPER_MAGIC: u64 = 0x6573_5546;

/// The inode number of a FUSE mount's key in [`EXECQ_ROOTS`]: the agent
/// keys it by the device alone (`agent/src/execq/kernel.rs`,
/// `FUSE_BY_DEVICE`; no inode is 0).
const FUSE_BY_DEVICE: u64 = 0;
/// [`fuse_dev`]: a FUSE superblock (the device in the low 32 bits).
const FUSE_DEV_FOUND: u64 = 1 << 32;
const FUSE_DEV_MASK: u64 = 0xffff_ffff;

/// Lot 318 (the review of #538, F1): the file of `dentry` is on a user
/// FUSE filesystem (its superblock's magic, and a type other than
/// `virtiofs`): [`FUSE_DEV_FOUND`] with the superblock's device, the key's
/// half the agent publishes; 0 otherwise. `virtiofs` shares the magic and
/// is a VM's or a Kata container's shared directory (its root filesystem,
/// at times): classed by its names and roots like any other — the agent's
/// mount table reader leaves it out of FUSE too. Without the type's
/// offsets (or a name that cannot be read) a FUSE-magic file is guarded.
#[inline(always)]
unsafe fn fuse_dev(dentry: *const u8) -> u64 {
    let inode = peek_u64(dentry.add(off!(DENTRY_D_INODE_OFFSET))) as *const u8;
    if inode.is_null() {
        return 0;
    }
    let sb = peek_u64(inode.add(off!(INODE_I_SB_OFFSET))) as *const u8;
    if sb.is_null() {
        return 0;
    }
    if peek_u64(sb.add(off!(SUPER_BLOCK_S_MAGIC_OFFSET))) != FUSE_SUPER_MAGIC {
        return 0;
    }
    if fs_type_is_virtiofs(sb) {
        return 0;
    }
    FUSE_DEV_FOUND | u64::from(peek_u32(sb.add(off!(SUPER_BLOCK_S_DEV_OFFSET))))
}

/// Whether superblock `sb`'s type is `virtiofs` (`sb->s_type->name`, its
/// first nine bytes: `wire::execq::is_virtiofs_name`). Optional offsets,
/// one at a time (5.15 rule 3).
#[inline(always)]
unsafe fn fs_type_is_virtiofs(sb: *const u8) -> bool {
    let Some(o_type) = off_opt!(SUPER_BLOCK_S_TYPE_OFFSET) else {
        return false;
    };
    let Some(o_name) = off_opt!(FILE_SYSTEM_TYPE_NAME_OFFSET) else {
        return false;
    };
    let ty = peek_u64(sb.add(o_type & 0xffff)) as *const u8;
    if ty.is_null() {
        return false;
    }
    let name = peek_u64(ty.add(o_name & 0xffff)) as *const u8;
    if name.is_null() {
        return false;
    }
    // Zeroed with volatile stores: `[0u64; 2]` would compile to a `memset`
    // call (rule 9); the string read stops at its NUL.
    let mut buf = core::mem::MaybeUninit::<[u64; 2]>::uninit();
    let wp = buf.as_mut_ptr() as *mut u64;
    core::ptr::write_volatile(wp, 0);
    core::ptr::write_volatile(wp.add(1), 0);
    if generated::bpf_probe_read_kernel_str(wp as *mut c_void, 16, name as *const c_void) < 0 {
        return false;
    }
    let w = buf.assume_init();
    northnarrow_common::wire::execq::is_virtiofs_name(w[0], w[1])
}

/// [`nn_guarded_root`]: an ancestor's key was found in [`EXECQ_ROOTS`] (its
/// value in the low 32 bits).
const GUARDED_ROOT_FOUND: u64 = 1 << 32;

/// Lot 318 (external bug hunt BUG108): the value in [`EXECQ_ROOTS`] of the
/// nearest ancestor of `dentry` whose key — `stat()`'s device and inode
/// number, as the agent publishes a guarded mount's root — is there, with
/// [`GUARDED_ROOT_FOUND`]; 0 when none is within [`EXE_WALK_DEPTH`] levels.
/// The search stops at `task_root`, the task's root (the re-check of #545,
/// R3): what lies above a container's or a chroot's root is not its view —
/// a container whose root is a directory in a home took that home's class.
/// For a task of the host the root is the top of its filesystem, and a
/// file of another filesystem never meets it. On btrfs each level's device
/// is its subvolume's (`SbDev`), so a subvolume's root (inode 256 under its
/// own device) is found where the walk crosses it. A global function
/// (integer arguments, never inlined): the verifier checks its loop once
/// (5.15 rule 6).
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_guarded_root(dentry: u64, task_root: u64) -> u64 {
    unsafe { guarded_root(dentry as *const u8, task_root as *const u8) }
}

#[inline(always)]
unsafe fn guarded_root(dentry: *const u8, task_root: *const u8) -> u64 {
    if dentry.is_null() {
        return 0;
    }
    let o_parent = off!(DENTRY_D_PARENT_OFFSET);
    let o_inode = off!(DENTRY_D_INODE_OFFSET);
    let o_ino = off!(INODE_I_INO_OFFSET);
    // The file's superblock is every ancestor's: `d_parent` stays in it.
    let file_inode = peek_u64(dentry.add(o_inode)) as *const u8;
    if file_inode.is_null() {
        return 0;
    }
    let sb = peek_u64(file_inode.add(off!(INODE_I_SB_OFFSET))) as *const u8;
    let devs = crate::inode_dev::SbDev::of(sb, peek_u32(sb.add(off!(SUPER_BLOCK_S_DEV_OFFSET))));
    // From the directory the file is in (a guarded root is a directory).
    let mut d = peek_u64(dentry.add(o_parent)) as *const u8;
    if d == dentry {
        return 0;
    }
    for _ in 0..EXE_WALK_DEPTH {
        if d.is_null() || d == task_root {
            break;
        }
        let inode = peek_u64(d.add(o_inode)) as *const u8;
        if !inode.is_null() {
            let key = ExecqKey {
                dev: u64::from(devs.dev(inode)),
                ino: peek_u64(inode.add(o_ino)),
            };
            if let Some(v) = EXECQ_ROOTS.get(&key) {
                return GUARDED_ROOT_FOUND | u64::from(*v);
            }
        }
        let up = peek_u64(d.add(o_parent)) as *const u8;
        if up == d {
            break;
        }
        d = up;
    }
    0
}

/// A binfmt pass of `bprm_check_security`, after `exec_lsm`'s walk filled
/// the scratch `s`. `inode` is the pass's file, `classes` its classes as
/// the exec policy leaves them to the guard (all of them without the
/// policy, lab PR 223); `task` the exec'ing `task_struct`; `pass` 0 for the
/// file the caller named. Returns the pass's verdict: `-EACCES` for a
/// script the guard would hold in enforce mode (lab PR 226), else 0.
#[inline(always)]
pub(crate) unsafe fn note_pass(
    s: *const ExeIdentityRaw,
    inode: *const u8,
    task: u64,
    pass: u8,
    classes: u32,
) -> i32 {
    let m = conf(conf_slot::MODE);
    if m == mode::OFF {
        return 0;
    }
    // A failed exec may have left a candidate; this exec starts afresh.
    if pass == 0 {
        cand_remove(task);
    } else if m == mode::ENFORCE {
        // Lab PR 226: the pass-0 candidate was a `#!` script (or a
        // binfmt_misc input) — this pass is its interpreter. Held, the
        // interpreter would open the script by its path once resumed, and
        // what it reads then need not be what was scanned: refused here,
        // before the point of no return.
        if let Some(cand) = EXECQ_CAND.get_ptr(&task) {
            if (*cand).flags & stop_flags::INTERP_PASS == 0 {
                let refused = refuse_script(cand, task);
                cand_remove(task);
                if refused {
                    return -EACCES;
                }
            }
        }
    }
    let c = classes & conf(conf_slot::CLASSES) as u32;
    let size = peek_u64(inode.add(off!(INODE_I_SIZE_OFFSET))) as i64;
    let mut cflags = 0u32;
    let mut ctime_sec = 0i64;
    let mut ctime_nsec = 0u32;
    match (off_opt!(INODE_I_CTIME_SEC_OFFSET), off_opt!(INODE_I_CTIME_NSEC_OFFSET)) {
        (Some(a), Some(b)) => {
            ctime_sec = peek_u64(inode.add(a & 0xffff)) as i64;
            ctime_nsec = peek_u32(inode.add(b & 0xffff));
        }
        _ => cflags |= stop_flags::NO_CTIME,
    }
    let mut known = false;
    if c != 0 && cflags & stop_flags::NO_CTIME == 0 {
        let key = ExecqKey {
            dev: (*s).dev,
            ino: (*s).ino,
        };
        if let Some(k) = EXECQ_KNOWN.get(&key) {
            known = k.ctime_sec == ctime_sec && k.ctime_nsec == ctime_nsec && k.size == size;
        }
    }
    if c == 0 || known {
        if known {
            bump(counter::KNOWN_SKIP);
        }
        // An interpreter nobody needs to judge: pass 0's candidate, if
        // any, was a script.
        if pass > 0 {
            if let Some(cand) = EXECQ_CAND.get_ptr_mut(&task) {
                if (*cand).flags & stop_flags::INTERP_PASS == 0 {
                    (*cand).flags |= stop_flags::SCRIPT;
                }
            }
        }
        return 0;
    }
    let ck = crate::task_scratch::current_key();
    let cand = match crate::task_scratch::make(&EXECQ_CAND_SCRATCH, &ck) {
        Some(p) => p,
        None => {
            bump(counter::CAND_DROPPED);
            crate::execpol::count_lost();
            return 0;
        }
    };
    (*cand).ctime_sec = ctime_sec;
    (*cand).ctime_nsec = ctime_nsec;
    (*cand).size = size;
    (*cand).class = c;
    (*cand).flags = cflags
        | if pass > 0 {
            stop_flags::INTERP_PASS
        } else {
            0
        };
    (*cand).uid = crate::task_scratch::current_uid();
    (*cand).inode = inode as u64;
    let _ = generated::bpf_probe_read_kernel(
        &mut (*cand).exe as *mut ExeIdentityRaw as *mut c_void,
        core::mem::size_of::<ExeIdentityRaw>() as u32,
        s as *const c_void,
    );
    let _ = nn_execq_cand_put(task, u64::from(ck.tid), ck.start_ns);
    0
}

/// The review of #547 (F4): the candidate built in the running task's
/// scratch entry ([`EXECQ_CAND_SCRATCH`], `tid`, `start`) copied into
/// [`EXECQ_CAND`] for `task` ([`cand_put`]), then the scratch entry removed.
/// A global function (integer arguments): the share's branches are checked
/// once, not on every way into the exec sensor's tail — inline, 5.15
/// refused `exec_check_lsm` past a million instructions.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_execq_cand_put(task: u64, tid: u64, start: u64) -> u64 {
    let ck = crate::task_scratch::key(tid, start);
    // SAFETY: the task's own scratch entry, then this module's maps.
    unsafe {
        if let Some(cand) = EXECQ_CAND_SCRATCH.get_ptr(&ck) {
            cand_put(task, cand);
        }
    }
    let _ = EXECQ_CAND_SCRATCH.remove(&ck);
    0
}

/// The review of #547 (F4): the candidate `cand` for `task`, within its
/// uid's share ([`EXECQ_CAND_PER_UID`]); past it, or the map full, dropped
/// (`CAND_DROPPED`: the exec runs unheld — the agent counts it as not held
/// and signs a degradation while it moves).
#[inline(always)]
unsafe fn cand_put(task: u64, cand: *const ExecqCandRaw) {
    cand_remove(task);
    let uid = (*cand).uid;
    if !crate::task_scratch::uid_admits(&EXECQ_CAND_UIDS, uid, EXECQ_CAND_PER_UID) {
        bump(counter::CAND_DROPPED);
        return;
    }
    if EXECQ_CAND.insert(&task, &*cand, 0).is_err() {
        bump(counter::CAND_DROPPED);
        return;
    }
    crate::task_scratch::uid_took(&EXECQ_CAND_UIDS, uid);
}

/// `task`'s candidate removed, its uid's share given back
/// ([`nn_execq_cand_remove`]).
#[inline(always)]
pub(crate) unsafe fn cand_remove(task: u64) {
    let _ = nn_execq_cand_remove(task);
}

/// `task`'s candidate removed, its uid's share given back. A global
/// function: called from every exec's pass (and `sched_process_exec`,
/// `task_free`, a failed exec's file), checked once.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_execq_cand_remove(task: u64) -> u64 {
    cand_take(task);
    0
}

/// `task_free`'s removal ([`crate::task_scratch::nn_task_free`]), inline:
/// the freed `task_struct` is a BTF pointer there, which a global
/// function's scalar argument refuses (5.15: "Caller passes invalid args").
#[inline(always)]
pub(crate) fn forget_freed(task: u64) {
    cand_take(task);
}

#[inline(always)]
fn cand_take(task: u64) {
    // SAFETY: a lookup and a delete in this module's maps.
    let uid = match unsafe { EXECQ_CAND.get(&task) } {
        Some(c) => c.uid,
        None => return,
    };
    if EXECQ_CAND.remove(&task).is_ok() {
        crate::task_scratch::uid_gave(&EXECQ_CAND_UIDS, uid);
    }
}

/// The review of #547 (F4): LSM `file_free_security`, in the task that held
/// the file (the kernel's last `fput` runs on the task's way back to user
/// mode). A failed exec's file — the pass's inode a candidate names — frees
/// that candidate: it stayed until the task's next exec or its end, and a
/// user's idle threads filled the map. A successful exec's candidate is
/// gone by then (`sched_process_exec`). One lookup per file freed while the
/// exec quarantine runs. A void hook.
#[lsm(hook = "file_free_security")]
pub fn execq_exec_failed(ctx: LsmContext) -> i32 {
    if conf(conf_slot::MODE) == mode::OFF {
        return 0;
    }
    let file: *const u8 = ctx.arg(0);
    unsafe {
        let task = aya_ebpf::helpers::bpf_get_current_task();
        let inode = match EXECQ_CAND.get(&task) {
            Some(c) => c.inode,
            None => return 0,
        };
        if !file.is_null() && peek_u64(file.add(off!(FILE_F_INODE_OFFSET))) == inode {
            cand_remove(task);
        }
    }
    0
}

/// Forget the exec's candidate (the exec policy refused the pass, a pass
/// without its walk, the task freed).
#[inline(always)]
pub(crate) unsafe fn forget(task: u64) {
    cand_remove(task);
}

/// Lab PR 226: report a script refused at its interpreter's pass, as a
/// candidate the kernel did not stop (`SCRIPT_REFUSED`). Fail-open like a
/// stop: without the agent's heartbeat, with a full ring, or for one of
/// the agent's own processes, nothing is refused (`false`).
#[inline(always)]
unsafe fn refuse_script(cand: *const ExecqCandRaw, task: u64) -> bool {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    if crate::task_kill::is_exempt_pid(tgid) {
        return false;
    }
    let now = bpf_ktime_get_ns();
    let beat = match EXECQ_ALIVE.get(0) {
        Some(v) => *v,
        None => 0,
    };
    if beat == 0 || (now > beat && now - beat > conf(conf_slot::HEARTBEAT_MAX_NS)) {
        bump(counter::STALE);
        return false;
    }
    let mut entry = match EXECQ_EVENTS.reserve::<ExecqStopRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::EXECQ);
            bump(counter::RING_FULL);
            return false;
        }
    };
    let raw: *mut ExecqStopRaw = entry.as_mut_ptr();
    crate::zero::zero(raw);
    let t = task as *const u8;
    let uid_gid = bpf_get_current_uid_gid();
    let parent = peek_u64(t.add(off!(TASK_STRUCT_REAL_PARENT_OFFSET))) as *const u8;
    (*raw).pid = tgid;
    (*raw).tid = pid_tgid as u32;
    (*raw).ppid = peek_u32(parent.add(off!(TASK_STRUCT_TGID_OFFSET)));
    (*raw).uid = (uid_gid & 0xFFFF_FFFF) as u32;
    (*raw).gid = (uid_gid >> 32) as u32;
    (*raw).timestamp_ns = now;
    (*raw).start_ns = peek_u64(t.add(off!(TASK_STRUCT_START_TIME_OFFSET)));
    (*raw).ctime_sec = (*cand).ctime_sec;
    (*raw).ctime_nsec = (*cand).ctime_nsec;
    (*raw).size = (*cand).size;
    (*raw).class = (*cand).class;
    (*raw).flags = (*cand).flags | stop_flags::SCRIPT | stop_flags::SCRIPT_REFUSED;
    (*raw).stop_rc = -EACCES;
    crate::comm::comm_into(&mut (*raw).comm);
    let _ = generated::bpf_probe_read_kernel(
        &mut (*raw).exe as *mut ExeIdentityRaw as *mut c_void,
        core::mem::size_of::<ExeIdentityRaw>() as u32,
        &(*cand).exe as *const ExeIdentityRaw as *const c_void,
    );
    entry.submit(0);
    bump(counter::SCRIPT_REFUSED);
    true
}

/// `sched_process_exec`, in the task that exec'd (`task`): report the
/// exec's candidate, and stop it in enforce mode.
#[inline(always)]
pub(crate) unsafe fn maybe_stop(task: *const u8) {
    let key = task as u64;
    let cand = match EXECQ_CAND.get_ptr(&key) {
        Some(c) => c,
        None => return,
    };
    let m = conf(conf_slot::MODE);
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    if m == mode::OFF || crate::task_kill::is_exempt_pid(tgid) {
        cand_remove(key);
        return;
    }
    let now = bpf_ktime_get_ns();
    let beat = match EXECQ_ALIVE.get(0) {
        Some(v) => *v,
        None => 0,
    };
    // Nobody listening: the process runs (fail-open), counted.
    if beat == 0 || (now > beat && now - beat > conf(conf_slot::HEARTBEAT_MAX_NS)) {
        bump(counter::STALE);
        cand_remove(key);
        return;
    }
    let mut entry = match EXECQ_EVENTS.reserve::<ExecqStopRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::EXECQ);
            bump(counter::RING_FULL);
            cand_remove(key);
            return;
        }
    };
    let raw: *mut ExecqStopRaw = entry.as_mut_ptr();
    crate::zero::zero(raw);
    let uid_gid = bpf_get_current_uid_gid();
    let start_ns = peek_u64(task.add(off!(TASK_STRUCT_START_TIME_OFFSET)));
    let parent = peek_u64(task.add(off!(TASK_STRUCT_REAL_PARENT_OFFSET))) as *const u8;
    (*raw).pid = tgid;
    (*raw).tid = pid_tgid as u32;
    (*raw).ppid = peek_u32(parent.add(off!(TASK_STRUCT_TGID_OFFSET)));
    (*raw).uid = (uid_gid & 0xFFFF_FFFF) as u32;
    (*raw).gid = (uid_gid >> 32) as u32;
    (*raw).timestamp_ns = now;
    (*raw).start_ns = start_ns;
    (*raw).ctime_sec = (*cand).ctime_sec;
    (*raw).ctime_nsec = (*cand).ctime_nsec;
    (*raw).size = (*cand).size;
    (*raw).class = (*cand).class;
    let mut flags = (*cand).flags;
    crate::comm::comm_into(&mut (*raw).comm);
    let _ = generated::bpf_probe_read_kernel(
        &mut (*raw).exe as *mut ExeIdentityRaw as *mut c_void,
        core::mem::size_of::<ExeIdentityRaw>() as u32,
        &(*cand).exe as *const ExeIdentityRaw as *const c_void,
    );
    cand_remove(key);
    if m == mode::ENFORCE {
        // Lot 317 (third bug hunt, review F3): the map names the process
        // before it is stopped, and a process the map cannot name is not
        // stopped (fail-open, counted): the map is what the agent's stop,
        // and the next start after a crash, resume — a stop it could not
        // take (4096 entries, not an LRU) stayed in state T for good.
        let v = ExecqStopped {
            start_ns,
            stop_ns: now,
        };
        if EXECQ_STOPPED.insert(&tgid, &v, 0).is_err() {
            flags |= stop_flags::MAP_FULL;
            bump(counter::MAP_FULL);
        } else {
            // Pending from here: delivered on the exit to user mode, before
            // the new image's first instruction.
            let rc = generated::bpf_send_signal(SIGSTOP);
            (*raw).stop_rc = rc as i32;
            if rc == 0 {
                bump(counter::STOPPED);
            } else {
                let _ = EXECQ_STOPPED.remove(&tgid);
                flags |= stop_flags::SIGNAL_FAILED;
                bump(counter::SIGNAL_FAILED);
            }
        }
    } else {
        flags |= stop_flags::OBSERVE;
        bump(counter::OBSERVED);
    }
    (*raw).flags = flags;
    entry.submit(0);
}
