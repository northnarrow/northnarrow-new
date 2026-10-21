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
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns, gen},
    macros::map,
    maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf},
};
use northnarrow_common::wire::exe::{exe_flags, exe_path_slot, ExeIdentityRaw, EXE_PATH_SLOT_LEN};
use northnarrow_common::wire::execq::{
    class, conf_slot, counter, mode, root_kind, stop_flags, ExecqCandRaw, ExecqKey, ExecqKnown,
    ExecqStopRaw, ExecqStopped,
};

use crate::btf_offsets::{
    DENTRY_D_INODE_OFFSET, DENTRY_D_PARENT_OFFSET, INODE_I_CTIME_NSEC_OFFSET,
    INODE_I_CTIME_SEC_OFFSET, INODE_I_MODE_OFFSET, INODE_I_SIZE_OFFSET, INODE_I_UID_OFFSET,
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
/// `ExeIdentityRaw::root_dev/root_ino`. Written by the agent.
#[map]
pub static EXECQ_ROOTS: HashMap<ExecqKey, u32> = HashMap::with_max_entries(64, 0);
/// The candidate of each exec in progress, keyed by `task_struct`.
#[map]
static EXECQ_CAND: LruHashMap<u64, ExecqCandRaw> = LruHashMap::with_max_entries(1024, 0);
/// Where a candidate is built (584 bytes: never on the stack).
#[map]
static EXECQ_CAND_SCRATCH: PerCpuArray<ExecqCandRaw> = PerCpuArray::with_max_entries(1, 0);
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
    let _ = gen::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 8, src as *const c_void);
    v.assume_init()
}

#[inline(always)]
unsafe fn peek_u32(src: *const u8) -> u32 {
    let mut v = core::mem::MaybeUninit::<u32>::uninit();
    let _ = gen::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 4, src as *const c_void);
    v.assume_init()
}

#[inline(always)]
unsafe fn peek_u16(src: *const u8) -> u16 {
    let mut v = core::mem::MaybeUninit::<u16>::uninit();
    let _ = gen::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 2, src as *const c_void);
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

/// The guarded classes of the file the walk just described (the per-CPU
/// scratch of `exec_lsm`). A global function (integer arguments, never
/// inlined): the verifier checks it once, apart from the LSM program.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_execq_classify(dentry: u64, flags: u64) -> u64 {
    unsafe {
        match crate::exec_lsm::EXEC_SCRATCH.get_ptr(0) {
            Some(s) => classify(s, dentry as *const u8, flags as u32) as u64,
            None => 0,
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
        return c;
    }
    let levels = (*s).levels as usize;
    if flags & exe_flags::TASK_ROOT != 0 {
        // Levels 0..levels-1 are the names below the task's root: the top
        // one is the first directory of the task's own view.
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
    } else {
        // The walk ended on a filesystem's root: a guarded mount, and
        // which point it is mounted at (lab PR 226).
        let key = ExecqKey {
            dev: (*s).root_dev,
            ino: (*s).root_ino,
        };
        if let Some(v) = EXECQ_ROOTS.get(&key) {
            let v = *v;
            c |= class::GUARDED_MOUNT;
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
        let _ = EXECQ_CAND.remove(&task);
    } else if m == mode::ENFORCE {
        // Lab PR 226: the pass-0 candidate was a `#!` script (or a
        // binfmt_misc input) — this pass is its interpreter. Held, the
        // interpreter would open the script by its path once resumed, and
        // what it reads then need not be what was scanned: refused here,
        // before the point of no return.
        if let Some(cand) = EXECQ_CAND.get_ptr(&task) {
            if (*cand).flags & stop_flags::INTERP_PASS == 0 {
                let refused = refuse_script(cand, task);
                let _ = EXECQ_CAND.remove(&task);
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
    let cand = match EXECQ_CAND_SCRATCH.get_ptr_mut(0) {
        Some(p) => p,
        None => return 0,
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
    (*cand)._pad = 0;
    let _ = gen::bpf_probe_read_kernel(
        &mut (*cand).exe as *mut ExeIdentityRaw as *mut c_void,
        core::mem::size_of::<ExeIdentityRaw>() as u32,
        s as *const c_void,
    );
    if EXECQ_CAND.insert(&task, &*cand, 0).is_err() {
        bump(counter::CAND_DROPPED);
    }
    0
}

/// Forget the exec's candidate (the exec policy refused the pass).
#[inline(always)]
pub(crate) unsafe fn forget(task: u64) {
    let _ = EXECQ_CAND.remove(&task);
}

/// Lab PR 226: report a script refused at its interpreter's pass, as a
/// candidate the kernel did not stop (`SCRIPT_REFUSED`). Fail-open like a
/// stop: without the agent's heartbeat, with a full ring, or for one of
/// the agent's own processes, nothing is refused (`false`).
#[inline(always)]
unsafe fn refuse_script(cand: *const ExecqCandRaw, task: u64) -> bool {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    if crate::task_kill::PROTECTED_PIDS.get(&tgid).is_some() {
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
    let _ = gen::bpf_probe_read_kernel(
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
    if m == mode::OFF || crate::task_kill::PROTECTED_PIDS.get(&tgid).is_some() {
        let _ = EXECQ_CAND.remove(&key);
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
        let _ = EXECQ_CAND.remove(&key);
        return;
    }
    let mut entry = match EXECQ_EVENTS.reserve::<ExecqStopRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::EXECQ);
            bump(counter::RING_FULL);
            let _ = EXECQ_CAND.remove(&key);
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
    let _ = gen::bpf_probe_read_kernel(
        &mut (*raw).exe as *mut ExeIdentityRaw as *mut c_void,
        core::mem::size_of::<ExeIdentityRaw>() as u32,
        &(*cand).exe as *const ExeIdentityRaw as *const c_void,
    );
    let _ = EXECQ_CAND.remove(&key);
    if m == mode::ENFORCE {
        // Pending from here: delivered on the exit to user mode, before
        // the new image's first instruction.
        let rc = gen::bpf_send_signal(SIGSTOP);
        (*raw).stop_rc = rc as i32;
        if rc == 0 {
            let v = ExecqStopped {
                start_ns,
                stop_ns: now,
            };
            let _ = EXECQ_STOPPED.insert(&tgid, &v, 0);
            bump(counter::STOPPED);
        } else {
            flags |= stop_flags::SIGNAL_FAILED;
            bump(counter::SIGNAL_FAILED);
        }
    } else {
        flags |= stop_flags::OBSERVE;
        bump(counter::OBSERVED);
    }
    (*raw).flags = flags;
    entry.submit(0);
}
