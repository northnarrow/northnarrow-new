//! Lab PR 226 (EXPERIMENTAL) — synchronous exec policies (CM-01) and the
//! exec environment / executable mapping checks (CM-25), the kernel half
//! (design `docs/design/EXEC_POLICY.md`, wire
//! `northnarrow_common::wire::execpol`).
//!
//! - [`on_pass`], from `exec_check_lsm` (LSM `bprm_check_security`), for
//!   each binfmt pass: the file's classes (lab PR 223's, plus `/dev/shm`,
//!   `/var/tmp` and the home of another user), the caller's lineage tier
//!   ([`nn_execpol_tier`]), the frozen policy → `-EACCES`, a "would deny"
//!   report, or the classes the exec quarantine may hold. On pass 0 the
//!   new environment is read and judged too ([`exec_env`]): a bounded
//!   prefix, the loader variables and the history tricks only
//!   ([`EnvStashRaw`]), from `envp` as the exec's own registers hold it.
//! - [`execmap_check`] (LSM `mmap_file`): an executable mapping of a file
//!   in a class, by the caller's tier → `-EACCES` or a report.
//!
//! Lot 322: the environment was read by two programs on the
//! `sys_enter_execve{,at}` tracepoints and handed to pass 0 through
//! `EXECPOL_ENV`. On Ubuntu 26.04's 7.0 a program on a syscall tracepoint
//! (attached, as aya and libbpf attach it, through a perf event opened on
//! CPU 0) ran only for the calls made on CPU 0: the check refused 0 of 11
//! staging preloads, 20 of 20 pinned to CPU 0, none pinned to CPU 1, 2 or
//! 3. At `bprm_check_security` the caller's memory is still its own (the
//! new image is mapped later, by the binfmt's `load_binary`): the
//! environment is read here, into the task's own entry, and the
//! environment's findings no longer cross from one program to another.
//! The kernel copied the strings earlier in the exec, into the new image's
//! stack, which is not readable here: this is a second read of the
//! caller's memory, and what changes it in between (another thread, a
//! process sharing the page) changes what is judged — the review of #546,
//! F2; reading the kernel's own copy is lot 325's. A string the scan
//! cannot read is a finding (`UNREADABLE`: counted, recorded), never
//! skipped.
//!
//! The exec's point of no return is past every one of these hooks: a deny
//! is the syscall's error, the caller keeps running its old image.
use aya_ebpf::{
    cty::c_void,
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_task,
        bpf_get_current_uid_gid, bpf_ktime_get_ns, generated,
    },
    macros::{lsm, map, tracepoint},
    maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::{LsmContext, TracePointContext},
    EbpfContext,
};
use northnarrow_common::wire::exe::{exe_flags, ExeIdentityRaw};
use northnarrow_common::wire::execpol::{
    action, conf_slot, counter, env_flags, env_name_wanted, envp_stride, envp_value,
    value_parse::{self, ValueParse}, ENV_COMMIT_ROUNDS, ENV_JUDGED_MAX, ENV_VALUE_READS,
    exec_envp_reg, flags, image_role, kind, mode, slice_slot, tier, tier_sig, EnvStashRaw,
    EnvpReg, ExecPolRaw, MapSeen, TaskKey, ENV_AUDIT_LEN, ENV_HIST_LEN, ENV_LIBPATH_LEN,
    ENV_PREFIX_LEN, ENV_PRELOAD_LEN, ENV_ROUNDS, ENV_SCAN_CAP, ENV_STEP, ENV_STEPS_MID,
    ENV_TUNABLES_LEN, MAP_REPORT_EVERY_NS,
};
use northnarrow_common::wire::execq::{class, ExecqKey};

use crate::btf_offsets::{
    DENTRY_D_INODE_OFFSET, DENTRY_D_NAME_OFFSET, DENTRY_D_PARENT_OFFSET, FILE_F_INODE_OFFSET,
    FILE_F_PATH_OFFSET, MM_STRUCT_ENV_END_OFFSET, MM_STRUCT_ENV_START_OFFSET,
    INODE_I_CTIME_NSEC_OFFSET, INODE_I_CTIME_SEC_OFFSET, INODE_I_INO_OFFSET, INODE_I_MODE_OFFSET,
    INODE_I_NLINK_OFFSET, INODE_I_SB_OFFSET, INODE_I_UID_OFFSET, LINUX_BINPRM_FILENAME_OFFSET,
    LINUX_BINPRM_FILE_OFFSET, LINUX_BINPRM_INTERP_OFFSET, MM_STRUCT_EXE_FILE_OFFSET,
    PATH_DENTRY_OFFSET, PT_REGS_DX_OFFSET, PT_REGS_ORIG_AX_OFFSET, PT_REGS_R10_OFFSET,
    PT_REGS_SI_OFFSET,
    QSTR_NAME_OFFSET, SIGNAL_STRUCT_TTY_OFFSET, SUPER_BLOCK_S_DEV_OFFSET,
    SUPER_BLOCK_S_MAGIC_OFFSET, TASK_STRUCT_FLAGS_OFFSET,
    TASK_STRUCT_LOGINUID_OFFSET, TASK_STRUCT_MM_OFFSET, TASK_STRUCT_REAL_PARENT_OFFSET,
    TASK_STRUCT_SIGNAL_OFFSET, TASK_STRUCT_START_TIME_OFFSET, TASK_STRUCT_TGID_OFFSET,
};

/// `EACCES`.
const EACCES: i32 = 13;
/// `SIGKILL`.
const SIGKILL: u32 = 9;
/// `S_IWOTH`.
const S_IWOTH: u16 = 0o002;
/// `PROT_EXEC`.
const PROT_EXEC: u64 = 0x4;
/// Hops of the lineage walked for an elevation binary.
const LINEAGE_HOPS: usize = 8;
/// Memory-backed filesystems (`TMPFS` flag), as in `exec_lsm`.
const TMPFS_MAGIC: u64 = 0x0102_1994;
const HUGETLBFS_MAGIC: u64 = 0x9584_58f6;
const RAMFS_MAGIC: u64 = 0x8584_58f6;
/// "memfd:" as the low six bytes of a little-endian u64.
const MEMFD_PREFIX: u64 = 0x3a64_666d_656d;
const MEMFD_MASK: u64 = 0xffff_ffff_ffff;

/// The policy — mode, per-tier class masks, environment and mapping
/// rules, flags — written once by the agent, then frozen.
#[map]
pub static EXECPOL_CONF: Array<u64> = Array::with_max_entries(conf_slot::SLOTS, 0);
/// The cgroup v2 ids of `system.slice` and `user.slice` (refreshed by the
/// agent: `user.slice` may appear after it starts).
#[map]
pub static EXECPOL_SLICES: Array<u64> = Array::with_max_entries(slice_slot::SLOTS, 0);
/// Executable images by `(dev, ino)`: elevation binaries, and the images
/// whose callers are exempt from some classes ([`image_role`]).
#[map]
pub static EXECPOL_IMAGES: HashMap<ExecqKey, u32> = HashMap::with_max_entries(256, 0);
/// The environment findings of an exec in progress (416 bytes: never on
/// the stack), in the exec'ing task's own entry ([`TaskKey`]: its thread
/// id and start time). Made, judged and removed at the exec's pass 0 in
/// one run of `exec_check_lsm` ([`exec_env`]); no other program reads it.
/// Lot 322: not a per-CPU scratch — an LSM program runs with migration
/// disabled but preemption enabled (`full` and `lazy` preemption, Ubuntu
/// 26.04's default), so another task's exec on the same CPU could rewrite
/// a per-CPU buffer between the scan and the judgment.
#[map]
static EXECPOL_ENV: HashMap<TaskKey, EnvScan> =
    HashMap::with_max_entries(crate::task_scratch::TASK_SCRATCH_CAP, 0);
/// The task's environment entry ([`EXECPOL_ENV`]): the findings the record
/// quotes, and (lot 325) the buffer [`execpol_env_commit`] reads the new
/// image's strings into.
#[repr(C)]
pub(crate) struct EnvScan {
    pub(crate) stash: EnvStashRaw,
    region: [u8; REGION_READ],
    /// The review of #547 (F1, F7): the value being judged, entry by entry.
    parse: ValueParse,
    /// The judged names read whole so far (F8: at most [`ENV_JUDGED_MAX`]).
    judged: u32,
    /// What only the scan uses ([`INTERNAL_*`](INTERNAL_BARE_PRELOAD)).
    internal: u32,
    /// The judged name a step stopped at (its string), for its round.
    pending: u64,
}
/// [`EnvScan::internal`]: a bare name in `LD_PRELOAD` / `LD_AUDIT`, a staging
/// or a relative directory in `LD_LIBRARY_PATH`, an `LD_LIBRARY_PATH` longer
/// than the scan reads — resolved together at the scan's end
/// ([`resolve_bare`]).
const INTERNAL_BARE_PRELOAD: u32 = 1 << 0;
const INTERNAL_BARE_AUDIT: u32 = 1 << 1;
const INTERNAL_LIBPATH_STAGING: u32 = 1 << 2;
const INTERNAL_LIBPATH_RELATIVE: u32 = 1 << 3;
const INTERNAL_LIBPATH_CUT: u32 = 1 << 4;
/// The review of #547 (F2, F5): the post-commit check's entry, one per CPU —
/// sound there: `execpol_env_commit` is a classic tracepoint program, which
/// runs with preemption off, so no other task's run can rewrite it — and
/// one the first pass, however many execs are in flight, cannot take.
#[map]
static COMMIT_ENV: PerCpuArray<EnvScan> = PerCpuArray::with_max_entries(1, 0);
/// Bytes of the new image's environment read at once by the post-commit
/// check ([`nn_env_region_step`]): a string shorter than this is one read.
const REGION_READ: usize = northnarrow_common::wire::execpol::ENV_REGION_READ;
const _: () = assert!(
    core::mem::size_of::<EnvScan>() == northnarrow_common::wire::execpol::ENV_ENTRY_BYTES
);
/// Lot 325 (TOCTOU): the staging loader findings the first pass saw and
/// let through (a tier whose rule records them), keyed by the exec'ing
/// `task_struct`, for [`execpol_env_commit`]: the kernel's copy holding a
/// staging entry the first pass did not see is the environment changed
/// after the copy. Written only then (rare), removed at the commit, at the
/// next exec's first pass and when the task is freed (`task_free`); a
/// plain hash: never evicted under a reader.
#[map]
static EXECPOL_ENV_SEEN: HashMap<u64, u32> = HashMap::with_max_entries(4096, 0);
/// One report per deny, "would deny", environment finding or mapping.
/// 256 KiB: about 240 reports of 1 056 bytes.
#[map]
pub static EXECPOL_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);
/// Per-CPU counters ([`counter`]).
#[map]
pub static EXECPOL_COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(counter::SLOTS, 0);
/// The classes of files mapped executable, by `(dev, ino)` and ctime, and
/// when they were last reported. Per agent run.
#[map]
static EXECMAP_SEEN: LruHashMap<ExecqKey, MapSeen> = LruHashMap::with_max_entries(16384, 0);
/// The mapping check's path walk (552 bytes), apart from the exec
/// sensor's: the mapping task's own entry, made by [`nn_map_classify`] and
/// removed before [`execmap_check`] returns. Lot 322: it was a per-CPU
/// buffer — rewritable by another task's mapping on the same CPU while
/// this one was preempted, and copied into a report from the cache with
/// whatever walk the CPU had made last (another file's path).
#[map]
pub(crate) static EXECMAP_SCRATCH: HashMap<TaskKey, ExeIdentityRaw> =
    HashMap::with_max_entries(crate::task_scratch::TASK_SCRATCH_CAP, 0);

#[inline(always)]
fn bump(slot: u32) {
    if let Some(c) = EXECPOL_COUNTERS.get_ptr_mut(slot) {
        // SAFETY: per-CPU slot, bounded by the map size.
        unsafe { *c = (*c).wrapping_add(1) };
    }
}

#[inline(always)]
fn conf(slot: u32) -> u64 {
    match EXECPOL_CONF.get(slot) {
        Some(v) => *v,
        None => 0,
    }
}

#[inline(always)]
fn slice(slot: u32) -> u64 {
    match EXECPOL_SLICES.get(slot) {
        Some(v) => *v,
        None => 0,
    }
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

/// `(dev, ino)` of `inode`, as `stat()` reports them.
#[inline(always)]
unsafe fn inode_key(inode: *const u8) -> ExecqKey {
    let sb = peek_u64(inode.add(off!(INODE_I_SB_OFFSET))) as *const u8;
    let s_dev = peek_u32(sb.add(off!(SUPER_BLOCK_S_DEV_OFFSET)));
    ExecqKey {
        dev: crate::inode_dev::stat_dev(inode, sb, s_dev) as u64,
        ino: peek_u64(inode.add(off!(INODE_I_INO_OFFSET))),
    }
}

/// The inode of `task`'s executable (`mm->exe_file->f_inode`); null for a
/// kernel thread.
#[inline(always)]
unsafe fn exe_inode(task: *const u8) -> *const u8 {
    let mm = peek_u64(task.add(off!(TASK_STRUCT_MM_OFFSET))) as *const u8;
    if mm.is_null() {
        return core::ptr::null();
    }
    let file = peek_u64(mm.add(off!(MM_STRUCT_EXE_FILE_OFFSET))) as *const u8;
    if file.is_null() {
        return core::ptr::null();
    }
    peek_u64(file.add(off!(FILE_F_INODE_OFFSET))) as *const u8
}

/// The `EXECPOL_IMAGES` role of `task`'s executable (0: none).
#[inline(always)]
unsafe fn image_role_of(task: *const u8) -> u32 {
    let inode = exe_inode(task);
    if inode.is_null() {
        return 0;
    }
    let key = inode_key(inode);
    match EXECPOL_IMAGES.get(&key) {
        Some(v) => *v,
        None => 0,
    }
}

/// The caller's lineage tier ([`tier`]) and the signals it rests on
/// ([`tier_sig`]). A global function (integer argument, never inlined):
/// the verifier checks its lineage loop once, apart from the hooks.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_execpol_tier(task: u64) -> u64 {
    unsafe { u64::from(tier_of(task as *const u8)) }
}

#[inline(always)]
unsafe fn tier_of(task: *const u8) -> u32 {
    let uid = bpf_get_current_uid_gid() as u32;
    let mut sig = 0u32;
    if uid == 0 {
        sig |= tier_sig::ROOT;
    }
    let sys = slice(slice_slot::SYSTEM);
    let user = slice(slice_slot::USER);
    if sys == 0 && user == 0 {
        return tier::UNKNOWN | sig | tier_sig::NO_SLICES;
    }
    // Level 1: the top-level slice the caller's cgroup is under. Lot 273d
    // (the short re-check of #497, NB5): the units' own `northnarrow.slice`
    // is a service slice, as `system.slice` was for them.
    let ours = slice(slice_slot::OURS);
    let cg1 = generated::bpf_get_current_ancestor_cgroup_id(1);
    if cg1 != 0 && cg1 == sys {
        return tier::SERVICE | sig | tier_sig::SYSTEM_SLICE;
    }
    // the last review of #497 (NC2): named as our slice
    if cg1 != 0 && cg1 == ours {
        return tier::SERVICE | sig | tier_sig::OUR_SLICE;
    }
    if cg1 == 0 || cg1 != user {
        return tier::UNKNOWN | sig;
    }
    sig |= tier_sig::USER_SLICE;
    let login = match off_opt!(TASK_STRUCT_LOGINUID_OFFSET) {
        Some(o) => peek_u32(task.add(o & 0xffff)),
        None => u32::MAX,
    };
    if login == u32::MAX {
        return tier::UNKNOWN | sig;
    }
    sig |= tier_sig::LOGIN;
    if let Some(o_sig) = off_opt!(TASK_STRUCT_SIGNAL_OFFSET) {
        if let Some(o_tty) = off_opt!(SIGNAL_STRUCT_TTY_OFFSET) {
            let signal = peek_u64(task.add(o_sig & 0xffff)) as *const u8;
            if !signal.is_null() && peek_u64(signal.add(o_tty & 0xffff)) != 0 {
                sig |= tier_sig::TTY;
            }
        }
    }
    if uid != 0 || sig & tier_sig::TTY == 0 {
        return tier::SESSION | sig;
    }
    // Root with a terminal in a login session: a root login, or an
    // elevation binary up the lineage (the caller itself included: the
    // child sudo forks has not exec'd yet).
    let mut t = task;
    let mut elevated = false;
    for _ in 0..LINEAGE_HOPS {
        if t.is_null() {
            break;
        }
        if image_role_of(t) & image_role::ELEVATION != 0 {
            elevated = true;
            break;
        }
        let up = peek_u64(t.add(off!(TASK_STRUCT_REAL_PARENT_OFFSET))) as *const u8;
        if up.is_null() || up == t || peek_u32(up.add(off!(TASK_STRUCT_TGID_OFFSET))) <= 1 {
            break;
        }
        t = up;
    }
    if elevated {
        sig |= tier_sig::ELEVATED;
    }
    if login == 0 || elevated {
        tier::ADMIN | sig
    } else {
        tier::SESSION | sig
    }
}

/// The classes of the caller's own exemptions for a file `inode`: those of
/// its image ([`image_role::EXEMPT_MASK`]), and memfd / deleted when the
/// exec re-runs the caller's own image. `sig` gets the reason.
#[inline(always)]
unsafe fn exemptions(task: *const u8, inode: *const u8, sig: &mut u32) -> u32 {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if tgid == 1 {
        // init: never refused (systemd ≥ 255 executes its executor from a
        // descriptor it pinned at start, deleted after an upgrade).
        *sig |= tier_sig::EXEMPT_IMAGE;
        return class::ALL;
    }
    let mut ex = 0u32;
    let own = exe_inode(task);
    if !own.is_null() {
        if own == inode {
            *sig |= tier_sig::SELF_REEXEC;
            ex |= class::MEMFD | class::DELETED;
        }
        let key = inode_key(own);
        if let Some(r) = EXECPOL_IMAGES.get(&key) {
            let e = *r & image_role::EXEMPT_MASK;
            if e != 0 {
                *sig |= tier_sig::EXEMPT_IMAGE;
                ex |= e;
            }
        }
    }
    ex
}

/// A binfmt pass of `bprm_check_security`, after `exec_lsm`'s walk filled
/// its scratch `s` (`inode`, `dentry`: the pass's file; `task` the
/// exec'ing `task_struct`, `wk` its key: `s` is its entry). Returns the
/// pass's verdict.
#[inline(always)]
pub(crate) unsafe fn on_pass(
    s: *const ExeIdentityRaw,
    inode: *const u8,
    dentry: *const u8,
    task: u64,
    pass: u8,
    wk: &TaskKey,
) -> i32 {
    let m = conf(conf_slot::MODE);
    let q = crate::execq::armed();
    if m == mode::OFF && !q {
        return 0;
    }
    let classes = crate::execq::nn_execq_classify(
        dentry as u64,
        (*s).flags as u64,
        u64::from(wk.tid),
        wk.start_ns,
    ) as u32;
    if m == mode::OFF {
        // Lab PR 223 alone: every class the guard holds.
        return crate::execq::note_pass(s, inode, task, pass, classes);
    }
    // The re-check of #547 (G6): the new environment is judged by its own
    // program on this hook ([`exec_env_lsm`]), not here.
    if classes == 0 {
        if q {
            return crate::execq::note_pass(s, inode, task, pass, 0);
        }
        return 0;
    }
    let t_ptr = task as *const u8;
    let tv = nn_execpol_tier(task) as u32;
    let t = tv & 3;
    let mut sig = tv & !tier::MASK;
    let mut act = 0u32;
    let mut cand = 0u32;
    if classes != 0 {
        let ex = exemptions(t_ptr, inode, &mut sig);
        let cells = classes & conf(conf_slot::DENY + t) as u32;
        let exempted = cells & ex;
        let cells = cells & !ex;
        let class_audit = conf(conf_slot::CLASS_AUDIT) as u32;
        let mut deny = cells & !class_audit;
        let mut would = (classes & conf(conf_slot::AUDIT + t) as u32 & !ex) | (cells & class_audit);
        if m != mode::ENFORCE {
            would |= deny;
            deny = 0;
        }
        if exempted != 0 {
            act |= action::EXEMPTED;
            bump(counter::EXEMPTED);
        }
        if deny != 0 {
            act |= action::DENY;
            bump(counter::DENIED);
        } else {
            let quar = classes & conf(conf_slot::QUARANTINE + t) as u32;
            if quar != 0 {
                if q {
                    act |= action::QUARANTINE;
                    bump(counter::QUARANTINE);
                } else {
                    act |= action::QUARANTINE_INACTIVE;
                    bump(counter::QUARANTINE_INACTIVE);
                }
            }
            cand = if conf(conf_slot::FLAGS) & flags::QUARANTINE_BY_POLICY != 0 {
                quar
            } else {
                classes
            };
        }
        if would != 0 {
            act |= action::WOULD_DENY;
            bump(counter::WOULD_DENY);
        }
    }
    if act & (action::DENY | action::WOULD_DENY) != 0 {
        let mode_bits = u32::from(peek_u16(inode.add(off!(INODE_I_MODE_OFFSET))));
        report_exec(s, inode, t_ptr, t | sig, classes, act, 0, 0, None, mode_bits);
    }
    if act & action::DENY != 0 {
        if pass == 0 {
            crate::execq::forget(task);
        }
        return -EACCES;
    }
    if q {
        return crate::execq::note_pass(s, inode, task, pass, cand);
    }
    0
}

// ── the environment's check: a program of its own (the re-check of #547) ──

/// The re-check of #547 (G6): the new environment judged at the exec's
/// first pass by a second LSM program on `bprm_check_security`, beside the
/// exec sensor's `exec_check_lsm`. The verifier gives each program its own
/// million instructions: with the scan inside it, 5.15 counted 930,372 for
/// `exec_check_lsm`. BPF-LSM runs the programs of a hook in turn and the
/// first refusal refuses the exec; `exec_check_lsm` is attached first (the
/// exec sensor, then the policy), so an exec refused on its classes is
/// recorded on them and not judged on its environment. Not a tail call:
/// under a tail call each frame is capped at 256 bytes, and the verdict
/// would cross a map. The judgment is lot 322's and lot 325's, moved:
/// refused where the tier's rule refuses a staging loader entry, or what
/// the scan cannot clear (`FIRST_PASS_FAIL_CLOSED`) at a protected or set-id
/// target; recorded; what it let through noted for the post-commit check.
#[lsm(hook = "bprm_check_security")]
pub fn exec_env_lsm(ctx: LsmContext) -> i32 {
    unsafe { try_exec_env_lsm(&ctx) }
}

#[inline(always)]
unsafe fn try_exec_env_lsm(ctx: &LsmContext) -> i32 {
    let m = conf(conf_slot::MODE);
    if m == mode::OFF || conf(conf_slot::FLAGS) & flags::ENV_SCAN == 0 {
        return 0;
    }
    // Kernel signature: (bprm).
    let bprm: *const u8 = ctx.arg(0);
    if bprm.is_null() {
        return 0;
    }
    let o_file = match off_opt!(LINUX_BINPRM_FILE_OFFSET) {
        Some(o) => o & 0xffff,
        None => return 0,
    };
    let o_filename = match off_opt!(LINUX_BINPRM_FILENAME_OFFSET) {
        Some(o) => o & 0xffff,
        None => return 0,
    };
    let o_interp = match off_opt!(LINUX_BINPRM_INTERP_OFFSET) {
        Some(o) => o & 0xffff,
        None => return 0,
    };
    // Pass 0 only: the file the caller named (an interpreter's pass runs
    // with the same environment).
    if peek_u64(bprm.add(o_interp)) != peek_u64(bprm.add(o_filename)) {
        return 0;
    }
    let file = peek_u64(bprm.add(o_file)) as *const u8;
    let inode = peek_u64(file.add(off!(FILE_F_INODE_OFFSET))) as *const u8;
    let dentry = peek_u64(file.add(off!(FILE_F_PATH_OFFSET) + off!(PATH_DENTRY_OFFSET))) as *const u8;
    let task = bpf_get_current_task();
    let wk = crate::task_scratch::current_key();
    // Lot 325: what an earlier, failed exec of this task left for the
    // post-commit check is not this exec's.
    let _ = EXECPOL_ENV_SEEN.remove(&task);
    // Lot 322: the new environment, read now into the task's own entry
    // (`ef` its findings, `stashed` whether the task's entry holds them:
    // removed once judged).
    let er = nn_exec_env(task, u64::from(wk.tid), wk.start_ns);
    let ef = er as u32;
    if ef == 0 {
        return 0;
    }
    let stashed = er & ENV_STASHED != 0;
    let tv = nn_execpol_tier(task) as u32;
    let t = tv & 3;
    let mode_bits = u32::from(peek_u16(inode.add(off!(INODE_I_MODE_OFFSET))));
    let mut env_act = 0u32;
    {
        let tb = 1u64 << t;
        // The target's set-id bits: what `GLIBC_TUNABLES` is reported at.
        let setid = mode_bits & 0o6000 != 0;
        // Lot 318 (external bug hunt BUG101): a set-id target is judged as
        // any other. It was let through on its mode bits ("the kernel sets
        // `AT_SECURE` and the loader ignores the entry"), which the bits do
        // not promise: root running a set-uid-root file changes no
        // credential, and no set-id bit applies under `no_new_privs`, on a
        // `nosuid` mount, to a `#!` script (its interpreter's bits decide)
        // or for an owner the caller's user namespace does not map.
        // `deny-root` was side-stepped with `su`, or with a set-gid copy of
        // anything run under `setpriv --no-new-privs`. Telling those apart
        // here would take four more kernel facts and could still miss one;
        // a preload from a staging path refused at a set-id target whose
        // loader would have ignored it costs nothing legitimate.
        let root = tv & tier_sig::ROOT != 0;
        let env_deny_rule = conf(conf_slot::ENV_DENY) & tb != 0
            || (root && conf(conf_slot::ENV_DENY_ROOT) & tb != 0);
        // Lot 325 (the re-check of #546, R2): an environment the scan could
        // not finish — longer than any the kernel accepts, so its array grew
        // after the kernel's count — is refused at a protected target (the
        // tier's rule refuses a staging preload) or a set-id one, and
        // recorded elsewhere. No legitimate environment reaches the cap
        // (the largest measured, a CI runner's or a Kubernetes pod's, holds
        // thousands of variables, the cap a million).
        // The review of #547: a relative loader path is the same (F1); a
        // loader value longer than the scan reads is not refused here (F7)
        // — the post-commit check judges the kernel's copy of it.
        let unfinished = ef & env_flags::FIRST_PASS_FAIL_CLOSED != 0 && (env_deny_rule || setid);
        if (ef & env_flags::DENYABLE != 0 && env_deny_rule) || unfinished {
            if m == mode::ENFORCE {
                env_act |= action::DENY;
                bump(counter::ENV_DENIED);
            } else {
                env_act |= action::WOULD_DENY;
            }
        }
        // The review of #546 (F1, F2): an environment not read whole is
        // counted and recorded, never refused (32-bit runtimes exec through
        // the compat calls; a string can go unreadable after the kernel's
        // copy).
        if ef & env_flags::UNREADABLE != 0 {
            bump(counter::ENV_UNREAD);
        }
        let reportable = ef
            & (env_flags::DENYABLE
                | env_flags::LIBPATH_STAGING
                | env_flags::HISTORY
                | env_flags::UNREADABLE
                | env_flags::UNFINISHED
                | env_flags::PRELOAD_RELATIVE
                | env_flags::LOADER_IRREGULAR)
            != 0
            || (setid && ef & env_flags::GLIBC_TUNABLES != 0);
        if conf(conf_slot::ENV_RECORD) & tb != 0 && reportable {
            env_act |= action::RECORD;
        }
        if env_act != 0 {
            bump(counter::ENV_RECORDED);
        }
        if ef & env_flags::UNFINISHED != 0 {
            bump(counter::ENV_TRUNCATED);
        }
    }
    if env_act != 0 {
        // one call: the record (its path walked) is checked once, not for
        // every state the judgment leaves
        nn_env_report(
            task,
            inode as u64,
            dentry as u64,
            (u64::from(tv) << 32) | u64::from(ef),
            (u64::from(env_act) << 32) | u64::from(mode_bits),
        );
    }
    if stashed {
        let _ = EXECPOL_ENV.remove(&wk);
    }
    // Lot 325 (TOCTOU): what was judged here and let through (a tier that
    // records it) is no news to the post-commit check — its record is
    // made; it still kills a protected target on what it cannot clear.
    if ef & (env_flags::DENYABLE | env_flags::UNJUDGED) != 0 && env_act & action::DENY == 0 {
        let _ = EXECPOL_ENV_SEEN.insert(&task, &ef, 0);
    }
    if env_act & action::DENY != 0 {
        // the exec quarantine's candidate of this pass, if `exec_check_lsm`
        // made one: the exec fails
        crate::execq::forget(task);
        return -EACCES;
    }
    0
}

/// The report of [`exec_env_lsm`]: the file by its identity and its path,
/// walked into the ring entry itself, and the environment's findings — the
/// values the record quotes from the task's entry ([`EXECPOL_ENV`], when
/// the scan stashed them). `tv_ef`: the tier above the findings;
/// `act_mode`: the action above the file's mode bits. A global function:
/// inline, its path walk was checked again for every state the judgment
/// left, past the verifier's budget on 5.15.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_env_report(task: u64, inode: u64, dentry: u64, tv_ef: u64, act_mode: u64) -> u64 {
    // SAFETY: the task's own entry, kernel reads of the exec's file.
    unsafe {
        let wk = crate::task_scratch::current_key();
        let env = match EXECPOL_ENV.get_ptr(&wk) {
            Some(e) => Some(&(*e).stash as *const EnvStashRaw),
            None => None,
        };
        report_env_pass(
            task as *const u8,
            inode as *const u8,
            dentry as *const u8,
            (tv_ef >> 32) as u32,
            tv_ef as u32,
            (act_mode >> 32) as u32,
            env,
            act_mode as u32,
        );
    }
    0
}

#[allow(clippy::too_many_arguments)]
#[inline(always)]
unsafe fn report_env_pass(
    task: *const u8,
    inode: *const u8,
    dentry: *const u8,
    tv: u32,
    ef: u32,
    env_act: u32,
    env: Option<*const EnvStashRaw>,
    mode_bits: u32,
) {
    let mut entry = match EXECPOL_EVENTS.reserve::<ExecPolRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::EXECPOL);
            bump(counter::RING_FULL);
            return;
        }
    };
    let raw: *mut ExecPolRaw = entry.as_mut_ptr();
    crate::zero::zero(raw);
    fill_head(raw, task);
    (*raw).kind = kind::EXEC;
    (*raw).tier = tv;
    (*raw).env_action = env_act;
    (*raw).env_flags = ef;
    if let Some(e) = env {
        (*raw).env_count = (*e).count;
        (*raw).tunables_len = (*e).tunables_len;
        let _ = generated::bpf_probe_read_kernel(
            (*raw).preload.as_mut_ptr() as *mut c_void,
            (ENV_PRELOAD_LEN + ENV_AUDIT_LEN + ENV_TUNABLES_LEN + ENV_LIBPATH_LEN + ENV_HIST_LEN)
                as u32,
            (*e).preload.as_ptr() as *const c_void,
        );
    }
    (*raw).file_mode = mode_bits;
    if let Some(o) = off_opt!(INODE_I_UID_OFFSET) {
        (*raw).file_uid = peek_u32(inode.add(o & 0xffff));
    }
    let k = inode_key(inode);
    let task_root = crate::exec_lsm::task_root_of(task);
    let wf = crate::exec_lsm::exe_walk(&mut (*raw).exe, dentry, task_root) as u32;
    (*raw).exe.dev = k.dev;
    (*raw).exe.ino = k.ino;
    (*raw).exe.flags = exe_flags::KNOWN | wf;
    entry.submit(0);
}

/// The common fields of a report.
#[inline(always)]
unsafe fn fill_head(raw: *mut ExecPolRaw, task: *const u8) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    (*raw).pid = (pid_tgid >> 32) as u32;
    (*raw).tid = pid_tgid as u32;
    let parent = peek_u64(task.add(off!(TASK_STRUCT_REAL_PARENT_OFFSET))) as *const u8;
    (*raw).ppid = peek_u32(parent.add(off!(TASK_STRUCT_TGID_OFFSET)));
    (*raw).uid = (uid_gid & 0xFFFF_FFFF) as u32;
    (*raw).gid = (uid_gid >> 32) as u32;
    (*raw).loginuid = match off_opt!(TASK_STRUCT_LOGINUID_OFFSET) {
        Some(o) => peek_u32(task.add(o & 0xffff)),
        None => u32::MAX,
    };
    (*raw).timestamp_ns = bpf_ktime_get_ns();
    (*raw).start_ns = peek_u64(task.add(off!(TASK_STRUCT_START_TIME_OFFSET)));
    (*raw).cgroup_id = generated::bpf_get_current_cgroup_id();
    crate::comm::comm_into(&mut (*raw).comm);
}

#[allow(clippy::too_many_arguments)]
#[inline(always)]
unsafe fn report_exec(
    s: *const ExeIdentityRaw,
    inode: *const u8,
    task: *const u8,
    tv: u32,
    classes: u32,
    act: u32,
    env_act: u32,
    ef: u32,
    env: Option<*const EnvStashRaw>,
    mode_bits: u32,
) {
    let mut entry = match EXECPOL_EVENTS.reserve::<ExecPolRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::EXECPOL);
            bump(counter::RING_FULL);
            return;
        }
    };
    let raw: *mut ExecPolRaw = entry.as_mut_ptr();
    crate::zero::zero(raw);
    fill_head(raw, task);
    (*raw).kind = kind::EXEC;
    (*raw).tier = tv;
    (*raw).classes = classes;
    (*raw).action = act;
    (*raw).env_action = env_act;
    (*raw).file_mode = mode_bits;
    if let Some(o) = off_opt!(INODE_I_UID_OFFSET) {
        (*raw).file_uid = peek_u32(inode.add(o & 0xffff));
    }
    (*raw).env_flags = ef;
    if let Some(e) = env {
        (*raw).env_count = (*e).count;
        (*raw).tunables_len = (*e).tunables_len;
        let _ = generated::bpf_probe_read_kernel(
            (*raw).preload.as_mut_ptr() as *mut c_void,
            (ENV_PRELOAD_LEN + ENV_AUDIT_LEN + ENV_TUNABLES_LEN + ENV_LIBPATH_LEN + ENV_HIST_LEN)
                as u32,
            (*e).preload.as_ptr() as *const c_void,
        );
    }
    let _ = generated::bpf_probe_read_kernel(
        &mut (*raw).exe as *mut ExeIdentityRaw as *mut c_void,
        core::mem::size_of::<ExeIdentityRaw>() as u32,
        s as *const c_void,
    );
    entry.submit(0);
}

// ── the new environment, at the exec's first pass ───────────────────

/// [`exec_envp`]'s values: not read; and the bit of a compat call's
/// `envp` (a user address is below 2^47: bit 63 is free).
const ENVP_UNREAD: u64 = u64::MAX;
const ENVP_COMPAT: u64 = 1 << 63;

/// [`env_scan`]'s result bit (above the 32 of [`env_flags`]): the task's
/// own entry could not be made (the map full: that many execs in flight):
/// nothing was read.
const SCAN_LOST: u64 = 1 << 32;

/// Lot 325: the task `task` (its `task_struct`) is being freed
/// (`task_free`): its note for the post-commit check goes.
#[inline(always)]
pub(crate) fn forget_freed(task: u64) {
    let _ = EXECPOL_ENV_SEEN.remove(&task);
}

/// The review of #546 (F5): a per-task buffer of the exec guards could not
/// be made (the map full) — counted ([`counter::LOST`]).
#[inline(always)]
pub(crate) fn count_lost() {
    bump(counter::LOST);
}

/// [`exec_env`]'s bit (above the 32 of [`env_flags`]): the task's entry
/// holds the findings (the caller removes it once judged).
const ENV_STASHED: u64 = 1 << 32;

/// [`exec_env`] as a global function (integer arguments): verified on its
/// own, apart from `exec_check_lsm`. Inlined there, 5.15's verifier
/// refused the program: on the unknown-call path the compiler spilled a
/// register that path never set ("R4 !read_ok").
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_exec_env(task: u64, tid: u64, start: u64) -> u64 {
    unsafe { exec_env(task as *const u8, &crate::task_scratch::key(tid, start)) }
}

/// The new environment of the exec in progress, read into the task's own
/// [`EXECPOL_ENV`] entry: its findings ([`env_flags`], 0 for none: the
/// entry is then gone) and [`ENV_STASHED`] when the entry holds them. Not
/// read whole: [`env_flags::UNREADABLE`] (the caller counts it and records
/// it) — a call [`exec_envp_reg`] does not know, a kernel without the
/// `pt_regs` offsets, an entry that could not be made, an array or a
/// string the scan could not read.
#[inline(always)]
unsafe fn exec_env(task: *const u8, key: &TaskKey) -> u64 {
    let raw = exec_envp(task);
    if raw == ENVP_UNREAD {
        return u64::from(env_flags::UNREADABLE);
    }
    if raw == 0 {
        return 0;
    }
    let compat = raw >> 63;
    let envp = raw & !ENVP_COMPAT;
    // Inline (not a global function of its own): lot 325's scan nests three
    // calls deep under it, and the verifier sums the frames of a call chain
    // (512 bytes): one frame less.
    let r = env_scan(envp, u64::from(key.tid), key.start_ns, compat);
    if r & SCAN_LOST != 0 {
        return u64::from(env_flags::UNREADABLE);
    }
    let ef = r as u32;
    if ef == 0 {
        return 0;
    }
    u64::from(ef) | ENV_STASHED
}

/// `envp` of the exec in progress, from the registers it entered the
/// kernel with (`task_pt_regs`), and whether it is an array of 32-bit
/// pointers (an ia32 or an x32 call: [`exec_envp_reg`], [`EnvpAbi`]; lot
/// 325, R1: an x32 call's register is read whole, an ia32 one's low half,
/// [`envp_value`]). The caller's memory is still its own at
/// `bprm_check_security`; the kernel copied the strings from it earlier in
/// the exec (into the new image's stack, which is not readable here), so
/// this is a second read of memory the caller — another thread, a process
/// sharing the page — can change in between: [`execpol_env_commit`] reads
/// the kernel's own copy once the exec is past its point of no return
/// (lot 325). 0: a task with no user call of its own (no `mm`: a
/// kernel-started exec; an io-wq worker carries another call's registers).
/// [`ENVP_UNREAD`]: not read (the offsets are not resolved: another
/// architecture; an unknown call). An array of 32-bit pointers carries
/// [`ENVP_COMPAT`].
#[inline(always)]
unsafe fn exec_envp(task: *const u8) -> u64 {
    // One value out, no tuple through the stack: on 5.15 an `Option<(u64,
    // bool)>` left a stack slot unwritten on one path and the verifier
    // refused the read ("invalid read from stack off -24").
    let ax = match off_opt!(PT_REGS_ORIG_AX_OFFSET) {
        Some(o) if o <= 0xff => o,
        _ => return ENVP_UNREAD,
    };
    if peek_u64(task.add(off!(TASK_STRUCT_MM_OFFSET))) == 0 {
        return 0;
    }
    let tflags = peek_u32(task.add(off!(TASK_STRUCT_FLAGS_OFFSET)));
    if !northnarrow_common::cgroup_limits::regs_are_the_writes(tflags) {
        return 0;
    }
    let regs = generated::bpf_task_pt_regs(generated::bpf_get_current_task_btf()) as u64;
    if regs == 0 {
        return ENVP_UNREAD;
    }
    let nr = peek_u64((regs + ax as u64) as *const u8);
    let (reg, abi) = match exec_envp_reg(nr) {
        Some(v) => v,
        None => return ENVP_UNREAD,
    };
    let off = match reg {
        EnvpReg::Dx => off_opt!(PT_REGS_DX_OFFSET),
        EnvpReg::R10 => off_opt!(PT_REGS_R10_OFFSET),
        EnvpReg::Si => off_opt!(PT_REGS_SI_OFFSET),
    };
    let off = match off {
        Some(o) if o <= 0xff => o,
        _ => return ENVP_UNREAD,
    };
    let v = envp_value(peek_u64((regs + off as u64) as *const u8), abi);
    if abi.compat_pointers() {
        v | ENVP_COMPAT
    } else {
        v
    }
}

/// "LD_PRELO", "LD_AUDIT", "LD_LIBRA", "GLIBC_TU", "HISTFILE",
/// "HISTSIZE", "HISTCONT" — the first eight bytes of the names, little
/// endian.
const W_LD_PRELO: u64 = u64::from_le_bytes(*b"LD_PRELO");
const W_LD_AUDIT: u64 = u64::from_le_bytes(*b"LD_AUDIT");
const W_LD_LIBRA: u64 = u64::from_le_bytes(*b"LD_LIBRA");
const W_RY_PATH: u64 = u64::from_le_bytes(*b"RY_PATH=");
const W_GLIBC_TU: u64 = u64::from_le_bytes(*b"GLIBC_TU");
const W_NABLES: u64 = u64::from_le_bytes(*b"NABLES=\0") & 0x00ff_ffff_ffff_ffff;
const W_HISTFILE: u64 = u64::from_le_bytes(*b"HISTFILE");
const W_HISTSIZE: u64 = u64::from_le_bytes(*b"HISTSIZE");
const W_HISTCONT: u64 = u64::from_le_bytes(*b"HISTCONT");
const W_ROL_IGNO: u64 = u64::from_le_bytes(*b"ROL=igno");
/// "AD=" (3 bytes), "=" (1), "SIZE=" (5), "=0\0" (3), "/dev/nul" (8).
const W_AD_EQ: u64 = 0x3d_4441;
const W_SIZE_EQ: u64 = 0x3d_455a_4953;
const W_EQ_ZERO: u64 = 0x00_303d;
const W_DEV_NUL: u64 = u64::from_le_bytes(*b"/dev/nul");
const M1: u64 = 0xff;
const M3: u64 = 0xff_ffff;
const M5: u64 = 0xff_ffff_ffff;
const M7: u64 = 0x00ff_ffff_ffff_ffff;

/// A step's or a round's result: the variables it read in the low 32 bits;
/// [`MORE`]: it read all it could take and the array goes on; [`UNREAD`]:
/// an entry or a name it could not read.
const COUNT_MASK: u64 = 0xffff_ffff;
const MORE: u64 = 1 << 63;
const UNREAD: u64 = 1 << 62;
/// A step stopped at a judged name (its string in [`EnvScan::pending`]):
/// the scan reads it whole ([`nn_env_pending`]); at the post-commit check,
/// the region's round. Steps never call down (the review of #547: the call
/// chain under `exec_check_lsm` stays under 512 bytes of stack).
const JUDGE: u64 = 1 << 61;
/// The scan stops before the array's end, not finished (`TRUNCATED`): the
/// judged names' cap was reached, or the task's entry went while a judged
/// name was read (it cannot: the task alone makes and removes it; were it
/// to, never a clean environment).
const STOP: u64 = 1 << 60;
/// The step calls of the post-commit check's round: its [`ENV_STEPS_MID`]
/// full steps and the stops at judged names.
const ROUND_CALLS: usize = ENV_STEPS_MID + ENV_JUDGED_MAX as usize;
// The first pass's rounds cover the cap: each full one reads
// ENV_STEPS_MID * ENV_STEP entries, and the scan runs ENV_ROUNDS of them
// beside its ENV_JUDGED_MAX stops at judged names.
const _: () = assert!(ENV_ROUNDS * ENV_STEPS_MID * ENV_STEP == ENV_SCAN_CAP);

/// Read the environment array `envp` (user memory of the caller, its old
/// image) into the task's own entry of [`EXECPOL_ENV`] (`tid`, `start`:
/// [`TaskKey`]), made here zeroed. Lot 325 (the re-check of #546, R2):
/// every variable, up to [`ENV_SCAN_CAP`] — above any environment the
/// kernel accepts ([`KERNEL_ENVC_MAX`]) — in [`ENV_ROUNDS`] rounds of
/// [`nn_env_round`]; each variable costs its pointer and its first eight
/// bytes, and the names the scan judges are read whole ([`nn_env_var`]).
/// It read the first 64 and flagged the rest `TRUNCATED`, neither refused
/// nor recorded: 64 padding variables hid an `LD_PRELOAD` after them.
/// `compat` (1): an array of 32-bit pointers. Returns the findings
/// ([`env_flags`]; with none the entry is removed) or [`SCAN_LOST`]. An
/// entry or a string it cannot read sets [`env_flags::UNREADABLE`] (the
/// review of #546, F2); an array longer than the cap,
/// [`env_flags::TRUNCATED`].
/// [`nn_exec_env`] (a global function) holds it inline: its rounds are
/// checked once there.

#[inline(always)]
unsafe fn env_scan(envp: u64, tid: u64, start: u64, compat: u64) -> u64 {
    let key = crate::task_scratch::key(tid, start);
    let e = match crate::task_scratch::make(&EXECPOL_ENV, &key) {
        Some(p) => p,
        None => return SCAN_LOST,
    };
    let stride = envp_stride(compat);
    let mut read = 0u64;
    let mut more = true;
    let mut round = 0usize;
    // What a round found goes into the entry at once, not into locals: each
    // way out of the loop is then one state for the verifier (5.15 refused
    // `exec_check_lsm` past a million instructions with two more). A round
    // reads ENV_STEPS_MID * ENV_STEP entries, unless the array ends or a
    // step stops at a judged name, which is read whole here
    // ([`nn_env_pending`]: past the judged names' cap, `STOP`); the rounds
    // and the judged names' stops cover the cap.
    while round < ENV_ROUNDS + ENV_JUDGED_MAX as usize {
        let r = nn_env_round(envp, read, tid, start, compat);
        read += r & COUNT_MASK;
        if r & UNREAD != 0 {
            (*e).stash.flags |= env_flags::UNREADABLE;
        }
        if r & JUDGE != 0 {
            if nn_env_pending(tid, start) & STOP != 0 {
                (*e).stash.flags |= env_flags::TRUNCATED;
                more = false;
                break;
            }
        } else if r & MORE == 0 {
            more = false;
            break;
        }
        round += 1;
    }
    if more {
        // Every round full: an array past the cap, longer than any the
        // kernel accepts — it grew after the kernel's count. Not judged
        // whole: refused where a staging preload is refused (on_pass).
        let mut ptr = 0u64;
        let rc = generated::bpf_probe_read_user(
            &mut ptr as *mut u64 as *mut c_void,
            stride as u32,
            (envp + read * stride) as *const c_void,
        );
        if rc != 0 || ptr != 0 {
            (*e).stash.flags |= env_flags::TRUNCATED;
        }
    }
    (*e).stash.count = read as u32;
    let f = nn_env_resolve(0, tid, start) as u32;
    if f == 0 {
        let _ = EXECPOL_ENV.remove(&key);
    }
    u64::from(f)
}

/// The review of #547 (F1): a bare name in `LD_PRELOAD` / `LD_AUDIT` is
/// searched in `LD_LIBRARY_PATH` first: under a staging directory there it
/// is a staging preload; under a relative one, a relative path; with a
/// library path longer than the scan reads, not judged to its end
/// (`LOADER_CUT`). The entry's findings then ([`env_entry`]: `sel`, `tid`,
/// `start`; [`env_flags::UNREADABLE`] without it). A global function: its
/// branches are checked once, not on every way out of a scan's loop.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_env_resolve(sel: u64, tid: u64, start: u64) -> u64 {
    unsafe {
        match env_entry(sel, tid, start) {
            Some(e) => {
                resolve_bare(e);
                u64::from((*e).stash.flags)
            }
            None => u64::from(env_flags::UNREADABLE),
        }
    }
}

#[inline(always)]
unsafe fn resolve_bare(e: *mut EnvScan) {
    let i = (*e).internal;
    if i & INTERNAL_BARE_PRELOAD != 0 && i & INTERNAL_LIBPATH_STAGING != 0 {
        (*e).stash.flags |= env_flags::PRELOAD_STAGING;
    }
    if i & INTERNAL_BARE_AUDIT != 0 && i & INTERNAL_LIBPATH_STAGING != 0 {
        (*e).stash.flags |= env_flags::AUDIT_STAGING;
    }
    if i & (INTERNAL_BARE_PRELOAD | INTERNAL_BARE_AUDIT) != 0 {
        if i & INTERNAL_LIBPATH_RELATIVE != 0 {
            (*e).stash.flags |= env_flags::PRELOAD_RELATIVE;
        }
        if i & INTERNAL_LIBPATH_CUT != 0 {
            (*e).stash.flags |= env_flags::LOADER_CUT;
        }
    }
}

/// The entry a judged name's functions work in: the exec'ing task's own
/// ([`EXECPOL_ENV`], `tid`, `start`) at the first pass (`sel` 0), the CPU's
/// ([`COMMIT_ENV`]) at the post-commit check (`sel` 1).
#[inline(always)]
unsafe fn env_entry(sel: u64, tid: u64, start: u64) -> Option<*mut EnvScan> {
    if sel != 0 {
        COMMIT_ENV.get_ptr_mut(0)
    } else {
        EXECPOL_ENV.get_ptr_mut(&crate::task_scratch::key(tid, start))
    }
}

/// The review of #547 (F8): one more judged name, or past the cap (the scan
/// is then not finished: `TRUNCATED`).
#[inline(always)]
unsafe fn judged_one_more(sel: u64, tid: u64, start: u64) -> bool {
    match env_entry(sel, tid, start) {
        Some(e) => {
            if (*e).judged >= ENV_JUDGED_MAX {
                (*e).stash.flags |= env_flags::TRUNCATED;
                false
            } else {
                (*e).judged += 1;
                true
            }
        }
        None => false,
    }
}

/// One round of [`env_scan`] from entry `idx`: up to [`ENV_STEPS_MID`] steps
/// ([`nn_env_step`]), until the array ends or a step stops at a judged name
/// (`JUDGE`, its string in [`EnvScan::pending`], for [`nn_env_pending`]).
/// Returns the entries read and the flags. A global function: checked once.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_env_round(envp: u64, idx: u64, tid: u64, start: u64, compat: u64) -> u64 {
    let mut n = 0u64;
    let mut unread = 0u64;
    let mut j = 0usize;
    while j < ENV_STEPS_MID {
        let r = nn_env_step(envp, idx + n, tid, start, compat);
        n += r & COUNT_MASK;
        unread |= r & UNREAD;
        if r & JUDGE != 0 {
            return n | unread | JUDGE;
        }
        if r & MORE == 0 {
            return n | unread;
        }
        j += 1;
    }
    n | unread | MORE
}

/// The judged name a step stopped at (the task's entry: `tid`, `start`),
/// read whole ([`nn_env_var`]) and, a loader variable, its value judged
/// ([`nn_env_judge`]) — at most [`ENV_JUDGED_MAX`] per exec
/// ([`judged_one_more`]: past it, `STOP`, the scan not finished). Called by
/// the scan itself, not by its round: the call chain under
/// `exec_check_lsm` stays under 512 bytes of stack, and the round's loop
/// stays small for the verifier. A global function: checked once.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_env_pending(tid: u64, start: u64) -> u64 {
    unsafe {
        if !judged_one_more(0, tid, start) {
            return STOP;
        }
        let ptr = match env_entry(0, tid, start) {
            Some(e) => (*e).pending,
            None => return STOP,
        };
        nn_env_judge(nn_env_var(ptr, tid, start, 0), ptr, tid, start, 0);
        if env_entry(0, tid, start).is_none() {
            return STOP;
        }
        0
    }
}

/// One step of [`env_scan`]: entries `idx..idx + ENV_STEP` of `envp`, each
/// its pointer and the first eight bytes of its string, read into the
/// task's entry (not the stack); it stops after a name the scan judges
/// ([`env_name_wanted`]), its string in [`EnvScan::pending`] (`JUDGE`), for
/// its round to read whole. A global function that calls nothing: its loop
/// is checked once, and the call chain stays short.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_env_step(envp: u64, idx: u64, tid: u64, start: u64, compat: u64) -> u64 {
    unsafe {
        let e = match env_entry(0, tid, start) {
            Some(x) => x,
            None => return UNREAD,
        };
        let w = (*e).region.as_mut_ptr() as *mut u64;
        let stride = envp_stride(compat);
        let mut unread = 0u64;
        let mut i = 0usize;
        while i < ENV_STEP {
            // the entry, into the buffer's third word (zeroed: a compat
            // entry fills its low half)
            core::ptr::write_volatile(w.add(2), 0);
            if generated::bpf_probe_read_user(
                w.add(2) as *mut c_void,
                stride as u32,
                (envp + (idx + i as u64) * stride) as *const c_void,
            ) != 0
            {
                return i as u64 | UNREAD;
            }
            let ptr = core::ptr::read_volatile(w.add(2));
            if ptr == 0 {
                return i as u64 | unread;
            }
            // The name's first eight bytes; the string read stops at its
            // NUL (a shorter name leaves zeroes, which no judged name has).
            core::ptr::write_volatile(w, 0);
            core::ptr::write_volatile(w.add(1), 0);
            if generated::bpf_probe_read_user_str(w as *mut c_void, 9, ptr as *const c_void) < 0 {
                unread = UNREAD;
            } else if env_name_wanted(core::ptr::read_volatile(w)) {
                (*e).pending = ptr;
                return (i + 1) as u64 | unread | JUDGE;
            }
            i += 1;
        }
        ENV_STEP as u64 | unread | MORE
    }
}

/// One variable at `ptr` whose name the scan judges, read into the entry
/// ([`env_entry`]: `sel`, `tid`, `start`): its first 24 bytes compared, a
/// loader variable's value captured for the record ([`scan_one`]); returns
/// which loader variable it is (`VAR_*`: [`nn_env_judge`] judges its value
/// whole). A global function: checked once, called for the few variables
/// it judges.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_env_var(ptr: u64, tid: u64, start: u64, sel: u64) -> u64 {
    unsafe {
        let e = match env_entry(sel, tid, start) {
            Some(p) => p,
            None => return VAR_NONE,
        };
        // Zeroed with volatile stores (the string read stops at its NUL
        // and the words are compared whole): `[0u64; 3]` compiled to a
        // `memset` call (rule 9).
        let mut buf = core::mem::MaybeUninit::<[u64; ENV_PREFIX_LEN / 8]>::uninit();
        let wp = buf.as_mut_ptr() as *mut u64;
        let mut z = 0;
        while z < ENV_PREFIX_LEN / 8 {
            core::ptr::write_volatile(wp.add(z), 0);
            z += 1;
        }
        if generated::bpf_probe_read_user_str(
            wp as *mut c_void,
            ENV_PREFIX_LEN as u32,
            ptr as *const c_void,
        ) < 0
        {
            (*e).stash.flags |= env_flags::UNREADABLE;
            return VAR_NONE;
        }
        let w = buf.assume_init();
        scan_one(e, ptr, w[0], w[1], w[2])
    }
}

/// [`nn_env_var`]'s result: the loader variable it captured (`VAR_*`), whose
/// value [`nn_env_judge`] then judges.
const VAR_NONE: u64 = 0;
const VAR_PRELOAD: u64 = 1;
const VAR_AUDIT: u64 = 2;
const VAR_LIBPATH: u64 = 3;

/// The loader variable [`nn_env_var`] just read (`var`, the variable at
/// `ptr`), its value judged whole — each occurrence, so a staging entry in
/// any of them is a finding (the mini-hunt: musl's loader takes the first
/// `LD_PRELOAD`, glibc's the last). The review of #547 (F1, F7): read
/// [`REGION_READ`] bytes at a time ([`nn_env_chunk`]), each entry parsed as
/// the loader parses the list and judged on its normalised path, up to
/// [`ENV_VALUE_READS`] reads (about 4 KiB) — past them, `LOADER_CUT`. It
/// compared the first nine bytes of each entry of a 128-byte capture: an
/// entry that started after its 119th byte, a `//tmp/`, a `/./tmp/`, a tab
/// (musl) passed; a clean value longer than the capture was refused.
/// A global function, beside [`nn_env_var`] rather than under it (the
/// verifier sums the frames of a call chain, 512 bytes): its reads are
/// checked once — inline in the round, its 16 reads multiplied the round's
/// states past the verifier's million instructions (7.0 refused
/// `exec_check_lsm`).
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_env_judge(var: u64, ptr: u64, tid: u64, start: u64, sel: u64) -> u64 {
    let (kind, off) = match var {
        VAR_PRELOAD => (u64::from(value_parse::KIND_PRELOAD), 11u64),
        VAR_AUDIT => (u64::from(value_parse::KIND_AUDIT), 9),
        VAR_LIBPATH => (u64::from(value_parse::KIND_LIBPATH), 16),
        _ => return 0,
    };
    let mut q = ptr + off;
    let mut r = 0usize;
    let mut cut = CHUNK_CUT;
    while r < ENV_VALUE_READS {
        let n = nn_env_chunk(q, kind | if r == 0 { CHUNK_FIRST } else { 0 }, tid, start, sel);
        if n < REGION_READ as u64 {
            // the value's end (0: unreadable, flagged)
            cut = 0;
            break;
        }
        q += (REGION_READ - 1) as u64;
        r += 1;
    }
    let _ = nn_env_chunk(0, kind | CHUNK_FINISH | cut, tid, start, sel);
    0
}

/// [`nn_env_chunk`]'s second argument, above the value's kind: the value's
/// first read (its parse starts afresh), the value's end (no read: its last
/// entry judged, what it showed into the findings), and with it, the value
/// went on past the reads.
const CHUNK_FIRST: u64 = 1 << 8;
const CHUNK_FINISH: u64 = 1 << 9;
const CHUNK_CUT: u64 = 1 << 10;

/// One read of a loader variable's value at `p` into the entry
/// ([`env_entry`]: `sel`, `tid`, `start`), up to [`REGION_READ`] bytes, its
/// bytes through the value's parser ([`value_parse::byte`]); returns the
/// bytes read with the NUL (0: unreadable, flagged). With [`CHUNK_FINISH`]
/// in `kind_flags`: no read — the value's end. A global function: its byte
/// loop is checked once.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_env_chunk(p: u64, kind_flags: u64, tid: u64, start: u64, sel: u64) -> u64 {
    unsafe {
        let e = match env_entry(sel, tid, start) {
            Some(x) => x,
            None => return 0,
        };
        let kind = (kind_flags & 0xff) as u32;
        if kind_flags & CHUNK_FINISH != 0 {
            value_found(e, kind, kind_flags & CHUNK_CUT != 0);
            return 0;
        }
        if kind_flags & CHUNK_FIRST != 0 {
            zero_parse(&mut (*e).parse);
        }
        let n = generated::bpf_probe_read_user_str(
            (*e).region.as_mut_ptr() as *mut c_void,
            REGION_READ as u32,
            p as *const c_void,
        );
        if n <= 0 {
            (*e).stash.flags |= env_flags::UNREADABLE;
            return 0;
        }
        // the bytes before the NUL (a full read: 255 and its NUL)
        let len = (n - 1) as usize;
        let buf = (*e).region.as_ptr();
        let mut i = 0usize;
        while i < REGION_READ - 1 {
            if i >= len {
                break;
            }
            // `value_parse::byte`, its separator and `/` steps in global
            // functions: inline, their branches multiplied the loop's
            // states past the verifier's million instructions
            let b = *buf.add(i);
            // the re-check of #547 (G1–G4): a control byte, a `$`
            value_parse::odd(&mut (*e).parse, b);
            if value_parse::is_sep(kind, b) {
                let _ = nn_value_end(u64::from(kind), tid, start, sel);
            } else {
                value_parse::begin(&mut (*e).parse, b);
                if b == b'/' {
                    let _ = nn_value_slash(tid, start, sel);
                } else {
                    value_parse::push(&mut (*e).parse, b);
                }
            }
            i += 1;
        }
        n as u64
    }
}

/// A separator of a value ([`value_parse::sep`]: its entry's end, an empty
/// `LD_LIBRARY_PATH` element) in the entry ([`env_entry`]: `sel`, `tid`,
/// `start`). A global function: checked once, called from
/// [`nn_env_chunk`]'s byte loop at each separator.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_value_end(kind: u64, tid: u64, start: u64, sel: u64) -> u64 {
    unsafe {
        if let Some(e) = env_entry(sel, tid, start) {
            value_parse::sep(&mut (*e).parse, kind as u32);
        }
    }
    0
}

/// A `/` of a value's entry ([`value_parse::slash`]), as [`nn_value_end`].
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_value_slash(tid: u64, start: u64, sel: u64) -> u64 {
    unsafe {
        if let Some(e) = env_entry(sel, tid, start) {
            value_parse::slash(&mut (*e).parse);
        }
    }
    0
}


/// Zero a [`ValueParse`] with volatile stores (a struct assignment compiled
/// to a `memset` call: rule 9).
#[inline(always)]
unsafe fn zero_parse(p: *mut ValueParse) {
    let w = p as *mut u64;
    let mut i = 0;
    while i < core::mem::size_of::<ValueParse>() / 8 {
        core::ptr::write_volatile(w.add(i), 0);
        i += 1;
    }
}

/// The end of a value: its last entry judged, what its entries showed into
/// the entry's findings; `cut`: the value went on past the reads.
#[inline(always)]
unsafe fn value_found(e: *mut EnvScan, kind: u32, cut: bool) {
    value_parse::end_value(&mut (*e).parse, kind);
    let found = (*e).parse.found;
    // the re-check of #547 (G1–G4): whichever loader variable
    if found & value_parse::IRREGULAR != 0 {
        (*e).stash.flags |= env_flags::LOADER_IRREGULAR;
    }
    let staging = found & value_parse::STAGING != 0;
    let relative = found & value_parse::RELATIVE != 0;
    let bare = found & value_parse::BARE != 0;
    let st = &mut (*e).stash;
    if kind == value_parse::KIND_PRELOAD {
        if staging {
            st.flags |= env_flags::PRELOAD_STAGING;
        }
        if relative {
            st.flags |= env_flags::PRELOAD_RELATIVE;
        }
        if bare {
            (*e).internal |= INTERNAL_BARE_PRELOAD;
        }
        if cut {
            st.flags |= env_flags::LOADER_CUT;
        }
    } else if kind == value_parse::KIND_AUDIT {
        if staging {
            st.flags |= env_flags::AUDIT_STAGING;
        }
        if relative {
            st.flags |= env_flags::PRELOAD_RELATIVE;
        }
        if bare {
            (*e).internal |= INTERNAL_BARE_AUDIT;
        }
        if cut {
            st.flags |= env_flags::LOADER_CUT;
        }
    } else {
        if staging {
            st.flags |= env_flags::LIBPATH_STAGING;
            (*e).internal |= INTERNAL_LIBPATH_STAGING;
        }
        if relative {
            st.flags |= env_flags::LIBPATH_STAGING;
            (*e).internal |= INTERNAL_LIBPATH_RELATIVE;
        }
        if cut {
            (*e).internal |= INTERNAL_LIBPATH_CUT;
        }
    }
}


/// Whether a captured value (`len` from the string read into `cap` bytes,
/// the value at `value`) was cut: a full read is `cap - 1` bytes and its NUL,
/// cut only when the value has a byte at `cap - 1` (the review of #547, F7:
/// a value of exactly 127 bytes, or 63, was flagged).
#[inline(always)]
unsafe fn value_cut(len: i64, cap: usize, value: u64) -> bool {
    if len < cap as i64 {
        return false;
    }
    let mut b = 0u8;
    let _ = generated::bpf_probe_read_user(
        &mut b as *mut u8 as *mut c_void,
        1,
        (value + cap as u64 - 1) as *const c_void,
    );
    b != 0
}

/// One variable (`ptr`, its first 24 bytes in `w0..w2`): a finding into the
/// task's entry `e`, and the value of a loader variable captured; returns
/// which (`VAR_*`: [`nn_env_judge`] judges each occurrence).
#[inline(always)]
unsafe fn scan_one(e: *mut EnvScan, ptr: u64, w0: u64, w1: u64, w2: u64) -> u64 {
    let st = &mut (*e).stash;
    if w0 == W_LD_PRELO && w1 & M3 == W_AD_EQ {
        st.flags |= env_flags::LD_PRELOAD;
        let len = generated::bpf_probe_read_user_str(
            st.preload.as_mut_ptr() as *mut c_void,
            ENV_PRELOAD_LEN as u32,
            (ptr + 11) as *const c_void,
        );
        if len < 0 {
            st.flags |= env_flags::UNREADABLE;
        }
        if value_cut(len, ENV_PRELOAD_LEN, ptr + 11) {
            st.flags |= env_flags::VALUE_CUT;
        }
        return VAR_PRELOAD;
    } else if w0 == W_LD_AUDIT && w1 & M1 == u64::from(b'=') {
        st.flags |= env_flags::LD_AUDIT;
        let len = generated::bpf_probe_read_user_str(
            st.audit.as_mut_ptr() as *mut c_void,
            ENV_AUDIT_LEN as u32,
            (ptr + 9) as *const c_void,
        );
        if len < 0 {
            st.flags |= env_flags::UNREADABLE;
        }
        if value_cut(len, ENV_AUDIT_LEN, ptr + 9) {
            st.flags |= env_flags::VALUE_CUT;
        }
        return VAR_AUDIT;
    } else if w0 == W_LD_LIBRA && w1 == W_RY_PATH {
        st.flags |= env_flags::LD_LIBRARY_PATH;
        let len = generated::bpf_probe_read_user_str(
            st.libpath.as_mut_ptr() as *mut c_void,
            ENV_LIBPATH_LEN as u32,
            (ptr + 16) as *const c_void,
        );
        if len < 0 {
            st.flags |= env_flags::UNREADABLE;
        }
        if value_cut(len, ENV_LIBPATH_LEN, ptr + 16) {
            st.flags |= env_flags::VALUE_CUT;
        }
        return VAR_LIBPATH;
    } else if w0 == W_GLIBC_TU && w1 & M7 == W_NABLES {
        st.flags |= env_flags::GLIBC_TUNABLES;
        let len = generated::bpf_probe_read_user_str(
            st.tunables.as_mut_ptr() as *mut c_void,
            ENV_TUNABLES_LEN as u32,
            (ptr + 15) as *const c_void,
        );
        if len < 0 {
            st.flags |= env_flags::UNREADABLE;
        }
        st.tunables_len = if len > 0 { (len - 1) as u32 } else { 0 };
    } else if w0 == W_HISTFILE && w1 & M1 == u64::from(b'=') {
        st.flags |= env_flags::HISTFILE;
        let hl = generated::bpf_probe_read_user_str(
            st.hist.as_mut_ptr() as *mut c_void,
            ENV_HIST_LEN as u32,
            (ptr + 9) as *const c_void,
        );
        if hl < 0 {
            st.flags |= env_flags::UNREADABLE;
        }
        // "HISTFILE=" then "/dev/null" or nothing.
        let v = (w1 >> 8) | (w2 << 56);
        if v & M1 == 0 || (v == W_DEV_NUL && (w2 >> 8) & 0xffff == 0x6c) {
            st.flags |= env_flags::HISTFILE_NULL;
        }
    } else if w0 == W_HISTFILE && w1 & M5 == W_SIZE_EQ {
        if (w1 >> 40) & 0xffff == 0x0030 {
            st.flags |= env_flags::HISTFILESIZE_ZERO;
        }
    } else if w0 == W_HISTSIZE && w1 & M3 == W_EQ_ZERO {
        st.flags |= env_flags::HISTSIZE_ZERO;
    } else if w0 == W_HISTCONT && w1 == W_ROL_IGNO {
        st.flags |= env_flags::HISTCONTROL_IGNORE;
    }
    VAR_NONE
}

// ── a flood of execs in flight: the ladder (lot 325, R5) ───────────

/// Lot 325 (the re-check of #546, R5): an exec whose walk could not be
/// made — the exec sensor's per-task map full: [`TASK_SCRATCH_CAP`]
/// (`crate::task_scratch`) execs preempted in the middle of the program, a
/// fork bomb's flood — judged on what needs no walk: the caller's tier,
/// the file's set-id bits, memfd, deleted, tmpfs, a world-writable
/// directory (`flags_pass`: the exec sensor's flags, the pass above bit
/// 32), and the environment (its own entry). Refused in enforce mode —
/// counted in [`counter::LOST`] — when those classes meet a deny cell, a
/// staging loader entry meets the tier's rule, or the environment could
/// not be read whole at a **protected target** (the tier's rule refuses a
/// staging preload, or the file is set-id). Every other exec runs,
/// counted in [`counter::LOST_OPEN`] and reported ([`action::UNWALKED`]):
/// the agent signs a degradation while either count moves. It refused
/// every exec (lot 322): a flood of execs in flight stopped the host's,
/// the administrator's shell's included. Returns 1 to refuse. A global
/// function: verified once, apart from `exec_check_lsm`.
///
/// [`TASK_SCRATCH_CAP`]: crate::task_scratch::TASK_SCRATCH_CAP
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_exec_unwalked(inode: u64, dentry: u64, task: u64, flags_pass: u64) -> u64 {
    unsafe {
        exec_unwalked(
            inode as *const u8,
            dentry as *const u8,
            task,
            flags_pass as u32,
            (flags_pass >> 32) as u8,
        )
    }
}

#[inline(always)]
unsafe fn exec_unwalked(
    inode: *const u8,
    dentry: *const u8,
    task: u64,
    fl: u32,
    pass: u8,
) -> u64 {
    let m = conf(conf_slot::MODE);
    if m == mode::OFF {
        // The exec quarantine alone: no candidate without the walk.
        bump(counter::LOST_OPEN);
        return 0;
    }
    let t_ptr = task as *const u8;
    let tv = nn_execpol_tier(task) as u32;
    let t = tv & 3;
    let mut sig = tv & !tier::MASK;
    // The classes that need no walk.
    let mut classes = 0u32;
    if fl & exe_flags::MEMFD != 0 {
        classes |= class::MEMFD;
    }
    if fl & exe_flags::DELETED != 0 {
        classes |= class::DELETED;
    }
    if fl & exe_flags::TMPFS != 0 {
        classes |= class::TMPFS;
    }
    let parent = peek_u64(dentry.add(off!(DENTRY_D_PARENT_OFFSET))) as *const u8;
    if !parent.is_null() && parent != dentry {
        let pinode = peek_u64(parent.add(off!(DENTRY_D_INODE_OFFSET))) as *const u8;
        if !pinode.is_null() && peek_u16(pinode.add(off!(INODE_I_MODE_OFFSET))) & S_IWOTH != 0 {
            classes |= class::WORLD_WRITABLE_DIR;
        }
    }
    let ex = exemptions(t_ptr, inode, &mut sig);
    let deny_c = classes & conf(conf_slot::DENY + t) as u32 & !ex & !(conf(conf_slot::CLASS_AUDIT) as u32);
    let mode_bits = u32::from(peek_u16(inode.add(off!(INODE_I_MODE_OFFSET))));
    // The re-check of #547 (G6): the environment is judged by its own
    // program ([`exec_env_lsm`]), which reads it into its own entry whether
    // or not this walk could be made.
    let mut act = action::UNWALKED | action::RECORD;
    let refuse = m == mode::ENFORCE && deny_c != 0;
    if refuse {
        bump(counter::LOST);
        act |= action::DENY;
    } else {
        bump(counter::LOST_OPEN);
        if deny_c != 0 {
            act |= action::WOULD_DENY;
        }
    }
    report_unwalked(inode, t_ptr, t | sig, classes, act, 0, 0, None, mode_bits, fl, pass);
    // The review of #547 (F4): an earlier, failed exec's candidate is not this
    // exec's (no candidate is made here: the quarantine needs the walk).
    if pass == 0 {
        crate::execq::forget(task);
    }
    if refuse {
        return 1;
    }
    0
}

/// The report of an exec judged without its walk: the file by its
/// identity (`dev`, `ino`) and the exec sensor's flags; no path.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
unsafe fn report_unwalked(
    inode: *const u8,
    task: *const u8,
    tv: u32,
    classes: u32,
    act: u32,
    env_act: u32,
    ef: u32,
    env: Option<*const EnvStashRaw>,
    mode_bits: u32,
    fl: u32,
    pass: u8,
) {
    let mut entry = match EXECPOL_EVENTS.reserve::<ExecPolRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::EXECPOL);
            bump(counter::RING_FULL);
            return;
        }
    };
    let raw: *mut ExecPolRaw = entry.as_mut_ptr();
    crate::zero::zero(raw);
    fill_head(raw, task);
    (*raw).kind = kind::EXEC;
    (*raw).tier = tv;
    (*raw).classes = classes;
    (*raw).action = act;
    (*raw).env_action = env_act;
    (*raw).file_mode = mode_bits;
    if let Some(o) = off_opt!(INODE_I_UID_OFFSET) {
        (*raw).file_uid = peek_u32(inode.add(o & 0xffff));
    }
    (*raw).env_flags = ef;
    if let Some(e) = env {
        (*raw).env_count = (*e).count;
        (*raw).tunables_len = (*e).tunables_len;
        let _ = generated::bpf_probe_read_kernel(
            (*raw).preload.as_mut_ptr() as *mut c_void,
            (ENV_PRELOAD_LEN + ENV_AUDIT_LEN + ENV_TUNABLES_LEN + ENV_LIBPATH_LEN + ENV_HIST_LEN)
                as u32,
            (*e).preload.as_ptr() as *const c_void,
        );
    }
    let key = inode_key(inode);
    (*raw).exe.dev = key.dev;
    (*raw).exe.ino = key.ino;
    (*raw).exe.flags = fl;
    (*raw).exe.pass = pass;
    entry.submit(0);
}

// ── the kernel's own copy, past the point of no return (lot 325) ─────

/// Lot 325 (TOCTOU; the review of #546, F2): the new image's environment
/// — the kernel's own copy of the strings, `[mm->env_start, mm->env_end)`
/// of the image the exec just mapped — read again at `sched_process_exec`,
/// once the exec is past its point of no return and before the image's
/// first instruction. The first pass ([`on_pass`]) reads the caller's
/// memory after the kernel copied it, and another thread of the caller, a
/// process sharing the page, or a FUSE-backed page can change it in
/// between: the kernel keeps the preload, the first pass sees none. No
/// other task shares the new image's memory (the exec ended every other
/// thread), so this read is the one the loader will see.
///
/// A staging loader entry here that the first pass did not see (or did not
/// let through: [`EXECPOL_ENV_SEEN`]) is the environment changed after the
/// kernel's copy (`env_flags::CHANGED`, counted in
/// [`counter::ENV_CHANGED`]): where the tier's rule refuses it, the image
/// is killed (`SIGKILL`, delivered before it returns to user mode; audit
/// mode: "would deny"), and it is reported. Reading the copy at
/// `bprm_check_security`, where the exec can still fail with `EACCES`, is
/// not possible: the new image's memory belongs to no task yet (no helper
/// reads an `mm` no task runs), and walking its page tables by hand takes
/// the direct map's KASLR base and the paging depth, which the BTF does not
/// give.
#[tracepoint]
pub fn execpol_env_commit(_ctx: TracePointContext) -> u32 {
    unsafe { env_commit() };
    0
}

#[inline(always)]
unsafe fn env_commit() {
    if conf(conf_slot::MODE) == mode::OFF || conf(conf_slot::FLAGS) & flags::ENV_SCAN == 0 {
        return;
    }
    let task = bpf_get_current_task() as *const u8;
    let tk = task as u64;
    let mm = peek_u64(task.add(off!(TASK_STRUCT_MM_OFFSET))) as *const u8;
    if mm.is_null() {
        return;
    }
    let (os, oe) = match (
        off_opt!(MM_STRUCT_ENV_START_OFFSET),
        off_opt!(MM_STRUCT_ENV_END_OFFSET),
    ) {
        (Some(a), Some(b)) => (a & 0xffff, b & 0xffff),
        _ => return,
    };
    let start = peek_u64(mm.add(os));
    let end = peek_u64(mm.add(oe));
    let seen = match EXECPOL_ENV_SEEN.get(&tk) {
        Some(v) => *v,
        None => 0,
    };
    if seen != 0 {
        let _ = EXECPOL_ENV_SEEN.remove(&tk);
    }
    // The CPU's entry (preemption is off here), zeroed.
    let e = match COMMIT_ENV.get_ptr_mut(0) {
        Some(p) => p,
        None => {
            bump(counter::ENV_UNREAD);
            return;
        }
    };
    if let Some(z) = crate::task_scratch::TASK_SCRATCH_ZERO.get_ptr(0) {
        let _ = generated::bpf_probe_read_kernel(
            e as *mut c_void,
            core::mem::size_of::<EnvScan>() as u32,
            z as *const c_void,
        );
    }
    let f = if end > start {
        nn_env_region(start, end) as u32
    } else {
        0
    };
    // The review of #547 (F2): a staging entry the first pass did not see
    // (the environment changed after the kernel's copy), and what this read
    // of the kernel's own copy cannot clear — a value longer than the scan
    // reads, past the bound of this read, a relative path, an unreadable
    // string — are never silent: a protected target (the tier's rule
    // refuses a staging preload) or a set-id one is killed, anything else
    // recorded and counted. It acted on new staging entries only.
    let staging_new = f & env_flags::DENYABLE & !seen;
    let unjudged = f & env_flags::UNJUDGED;
    if staging_new == 0 && unjudged == 0 {
        return;
    }
    let tv = nn_execpol_tier(tk) as u32;
    let t = tv & 3;
    let tb = 1u64 << t;
    let root = tv & tier_sig::ROOT != 0;
    let rule = conf(conf_slot::ENV_DENY) & tb != 0
        || (root && conf(conf_slot::ENV_DENY_ROOT) & tb != 0);
    let setid = exe_mode(mm) & 0o6000 != 0;
    let kill = (staging_new != 0 && rule) || (unjudged != 0 && (rule || setid));
    // what the first pass judged and recorded, let through: no news, unless
    // it is to be killed now
    if !kill && staging_new == 0 && unjudged & !seen == 0 {
        return;
    }
    if staging_new != 0 {
        bump(counter::ENV_CHANGED);
    }
    if unjudged & env_flags::UNFINISHED != 0 {
        bump(counter::ENV_TRUNCATED);
    }
    if unjudged & env_flags::UNREADABLE != 0 {
        bump(counter::ENV_UNREAD);
    }
    let mut env_act = action::RECORD;
    if kill {
        if conf(conf_slot::MODE) == mode::ENFORCE {
            // the review of #547 (F9): killed only when the signal is sent
            if generated::bpf_send_signal(SIGKILL) == 0 {
                env_act |= action::DENY | action::KILLED;
                bump(counter::ENV_DENIED);
            } else {
                env_act |= action::WOULD_DENY;
            }
        } else {
            env_act |= action::WOULD_DENY;
        }
    }
    bump(counter::ENV_RECORDED);
    let changed = if staging_new != 0 { env_flags::CHANGED } else { 0 };
    report_commit(task, mm, tv, f | changed, env_act, &(*e).stash);
}

/// The mode bits of `mm`'s executable (0 when unreadable).
#[inline(always)]
unsafe fn exe_mode(mm: *const u8) -> u32 {
    let file = peek_u64(mm.add(off!(MM_STRUCT_EXE_FILE_OFFSET))) as *const u8;
    if file.is_null() {
        return 0;
    }
    let inode = peek_u64(file.add(off!(FILE_F_INODE_OFFSET))) as *const u8;
    if inode.is_null() {
        return 0;
    }
    u32::from(peek_u16(inode.add(off!(INODE_I_MODE_OFFSET))))
}

/// The report of [`execpol_env_commit`]: the new image's file, its path
/// walked into the ring entry itself.
#[inline(always)]
unsafe fn report_commit(
    task: *const u8,
    mm: *const u8,
    tv: u32,
    ef: u32,
    env_act: u32,
    e: *const EnvStashRaw,
) {
    let mut entry = match EXECPOL_EVENTS.reserve::<ExecPolRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::EXECPOL);
            bump(counter::RING_FULL);
            return;
        }
    };
    let raw: *mut ExecPolRaw = entry.as_mut_ptr();
    crate::zero::zero(raw);
    fill_head(raw, task);
    (*raw).kind = kind::EXEC;
    (*raw).tier = tv;
    (*raw).env_action = env_act;
    (*raw).env_flags = ef;
    (*raw).env_count = (*e).count;
    (*raw).tunables_len = (*e).tunables_len;
    let _ = generated::bpf_probe_read_kernel(
        (*raw).preload.as_mut_ptr() as *mut c_void,
        (ENV_PRELOAD_LEN + ENV_AUDIT_LEN + ENV_TUNABLES_LEN + ENV_LIBPATH_LEN + ENV_HIST_LEN) as u32,
        (*e).preload.as_ptr() as *const c_void,
    );
    let file = peek_u64(mm.add(off!(MM_STRUCT_EXE_FILE_OFFSET))) as *const u8;
    if !file.is_null() {
        let inode = peek_u64(file.add(off!(FILE_F_INODE_OFFSET))) as *const u8;
        if !inode.is_null() {
            let k = inode_key(inode);
            (*raw).file_mode = u32::from(peek_u16(inode.add(off!(INODE_I_MODE_OFFSET))));
            if let Some(o) = off_opt!(INODE_I_UID_OFFSET) {
                (*raw).file_uid = peek_u32(inode.add(o & 0xffff));
            }
            let dentry =
                peek_u64(file.add(off!(FILE_F_PATH_OFFSET) + off!(PATH_DENTRY_OFFSET))) as *const u8;
            let task_root = crate::exec_lsm::task_root_of(task);
            let wf = crate::exec_lsm::exe_walk(&mut (*raw).exe, dentry, task_root) as u32;
            (*raw).exe.dev = k.dev;
            (*raw).exe.ino = k.ino;
            (*raw).exe.flags = exe_flags::KNOWN | wf;
        }
    }
    entry.submit(0);
}

/// The new image's environment `[start, end)`, string after string, into
/// the CPU's entry ([`COMMIT_ENV`]): at most [`ENV_COMMIT_ROUNDS`] rounds of
/// [`nn_env_region_round`] (the review of #547, F8: with preemption off, at
/// most 98,304 reads of the strings, and the judged names' values; past
/// them, `TRUNCATED`), each string's first eight
/// bytes compared and the judged names read whole, their values judged as
/// the first pass judges them ([`nn_env_var`], [`nn_env_judge`]). Returns
/// the findings. A global function: checked once.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_env_region(start: u64, end: u64) -> u64 {
    unsafe {
        let e = match COMMIT_ENV.get_ptr_mut(0) {
            Some(p) => p,
            None => return u64::from(env_flags::UNREADABLE),
        };
        let mut pos = start;
        let mut at = 1u64;
        let mut done = false;
        let mut round = 0usize;
        while round < ENV_COMMIT_ROUNDS {
            let r = nn_env_region_round(pos, end, at);
            if r & UNREAD != 0 {
                (*e).stash.flags |= env_flags::UNREADABLE;
                done = true;
                break;
            }
            if r & (MORE | STOP) != MORE {
                done = true;
                break;
            }
            pos = r & POS_MASK;
            at = (r >> AT_SHIFT) & AT_MASK;
            round += 1;
        }
        if !done {
            (*e).stash.flags |= env_flags::TRUNCATED;
        }
        nn_env_resolve(1, 0, 0)
    }
}

/// A region step's or round's result: the position reached (a user
/// address, below 2^48), and whether it is at a string's start.
const POS_MASK: u64 = (1 << 48) - 1;
const AT_SHIFT: u64 = 48;
/// The position's bits above it: at a string's start; and that string is
/// the judged one just read whole (its name is not compared again).
const AT_START: u64 = 1;
const AT_SKIP: u64 = 2;
const AT_MASK: u64 = AT_START | AT_SKIP;

/// One round of [`nn_env_region`]: steps ([`nn_env_region_step`]); each
/// judged name a step stops at is read whole here, its value judged, then
/// its string skipped by the next step.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_env_region_round(pos: u64, end: u64, at: u64) -> u64 {
    unsafe {
        let mut p = pos;
        let mut a = at & AT_MASK;
        let mut j = 0usize;
        while j < ROUND_CALLS {
            let r = nn_env_region_step(p, end, a);
            if r & UNREAD != 0 {
                return r;
            }
            p = r & POS_MASK;
            a = (r >> AT_SHIFT) & AT_MASK;
            if r & JUDGE != 0 {
                if !judged_one_more(1, 0, 0) {
                    return p | STOP;
                }
                nn_env_judge(nn_env_var(p, 0, 0, 1), p, 0, 0, 1);
                // the string at `p` again, its name not compared
                a = AT_START | AT_SKIP;
            } else if r & MORE == 0 {
                return r;
            }
            j += 1;
        }
        p | (a << AT_SHIFT) | MORE
    }
}

/// One step of [`nn_env_region`]: [`ENV_STEP`] reads of up to
/// [`REGION_READ`] bytes; a read that starts a string compares its first
/// eight bytes — a judged name stops the step at that string (`JUDGE`) for
/// its round, which reads it whole and has the next step skip it
/// ([`AT_SKIP`]) — and a string longer than a read takes the next one. A
/// global function that calls nothing.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_env_region_step(pos: u64, end: u64, at: u64) -> u64 {
    unsafe {
        let e = match COMMIT_ENV.get_ptr_mut(0) {
            Some(p) => p,
            None => return pos | UNREAD,
        };
        let mut p = pos;
        let mut a = at & AT_START;
        let mut skip = at & AT_SKIP != 0;
        let mut i = 0usize;
        while i < ENV_STEP {
            if p >= end {
                return p | (a << AT_SHIFT);
            }
            let n = generated::bpf_probe_read_user_str(
                (*e).region.as_mut_ptr() as *mut c_void,
                REGION_READ as u32,
                p as *const c_void,
            );
            if n <= 0 {
                return p | UNREAD;
            }
            if a != 0 {
                if !skip {
                    (*e).stash.count = (*e).stash.count.wrapping_add(1);
                    // Bytes past the NUL are an earlier read's: a judged
                    // name has no NUL in its first eight bytes.
                    if env_name_wanted(core::ptr::read_volatile(
                        (*e).region.as_ptr() as *const u64,
                    )) {
                        return p | (AT_START << AT_SHIFT) | JUDGE;
                    }
                }
                skip = false;
            }
            if n < REGION_READ as i64 {
                p += n as u64;
                a = AT_START;
            } else {
                p += (REGION_READ - 1) as u64;
                a = 0;
            }
            i += 1;
        }
        p | (a << AT_SHIFT) | MORE
    }
}




// ── executable mappings ─────────────────────────────────────────────

/// Argument `i` of the hook, read from the context without the verifier's
/// BTF typing (a scalar).
#[inline(always)]
unsafe fn raw_arg(ctx: &LsmContext, i: usize) -> u64 {
    let args = ctx.as_ptr() as *const u64;
    let mut v = 0u64;
    let _ = generated::bpf_probe_read_kernel(
        &mut v as *mut u64 as *mut c_void,
        8,
        args.add(i) as *const c_void,
    );
    v
}

#[lsm(hook = "mmap_file")]
pub fn execmap_check(ctx: LsmContext) -> i32 {
    unsafe {
        let task = bpf_get_current_task() as *const u8;
        let mut walked: Option<TaskKey> = None;
        let rc = try_execmap(&ctx, task, &mut walked);
        if let Some(k) = &walked {
            let _ = EXECMAP_SCRATCH.remove(k);
        }
        rc
    }
}

/// `walked`: set once the task's walk entry is made (the caller removes it).
#[inline(always)]
unsafe fn try_execmap(ctx: &LsmContext, task: *const u8, walked: &mut Option<TaskKey>) -> i32 {
    // Kernel signature (5.15–6.18): (file, reqprot, prot, flags). `reqprot`
    // is what the caller asked; PROT_EXEC in it is an executable mapping.
    // The file is read through a helper, untyped: it is handed to a global
    // function, which takes scalars only.
    let file = raw_arg(ctx, 0) as *const u8;
    let reqprot = raw_arg(ctx, 1);
    if file.is_null() || reqprot & PROT_EXEC == 0 {
        return 0;
    }
    let m = conf(conf_slot::MODE);
    if m == mode::OFF || conf(conf_slot::FLAGS) & flags::MAP == 0 {
        return 0;
    }
    // The image an exec is loading (`mm->exe_file`): judged at its exec.
    let mm = peek_u64(task.add(off!(TASK_STRUCT_MM_OFFSET))) as *const u8;
    if mm.is_null() || peek_u64(mm.add(off!(MM_STRUCT_EXE_FILE_OFFSET))) as *const u8 == file {
        return 0;
    }
    let inode = peek_u64(file.add(off!(FILE_F_INODE_OFFSET))) as *const u8;
    if inode.is_null() {
        return 0;
    }
    let key = inode_key(inode);
    let (cs, cn) = match (off_opt!(INODE_I_CTIME_SEC_OFFSET), off_opt!(INODE_I_CTIME_NSEC_OFFSET)) {
        (Some(a), Some(b)) => (
            peek_u64(inode.add(a & 0xffff)) as i64,
            peek_u32(inode.add(b & 0xffff)),
        ),
        _ => (0i64, 0u32),
    };
    let mut classes = 0u32;
    let mut reported = 0u64;
    let mut cached = false;
    if let Some(v) = EXECMAP_SEEN.get(&key) {
        if v.ctime_sec == cs && v.ctime_nsec == cn {
            classes = v.classes;
            reported = v.reported_ns;
            cached = true;
        }
    }
    let wk = crate::task_scratch::key_of(task);
    if !cached {
        *walked = Some(wk);
        let r = nn_map_classify(file as u64, u64::from(wk.tid), wk.start_ns) as u32;
        classes = r & !MAP_WALK_LOST;
        // A classification without a walk (fail-closed) is not cached:
        // the next mapping of the file is walked.
        if r & MAP_WALK_LOST == 0 {
            let v = MapSeen {
                ctime_sec: cs,
                ctime_nsec: cn,
                classes,
                reported_ns: 0,
            };
            let _ = EXECMAP_SEEN.insert(&key, &v, 0);
        }
    }
    if classes == 0 {
        return 0;
    }
    let tv = nn_execpol_tier(task as u64) as u32;
    let t = tv & 3;
    let deny_c = classes & conf(conf_slot::MAP_DENY + t) as u32;
    let rec_c = classes & conf(conf_slot::MAP_RECORD + t) as u32;
    if deny_c == 0 && rec_c == 0 {
        return 0;
    }
    let mut act = action::RECORD;
    let mut rc = 0;
    if deny_c != 0 {
        if m == mode::ENFORCE && deny_c & !(conf(conf_slot::CLASS_AUDIT) as u32) != 0 {
            act |= action::DENY;
            rc = -EACCES;
            bump(counter::MAP_DENIED);
        } else {
            act |= action::WOULD_DENY;
        }
    }
    bump(counter::MAP_RECORDED);
    // One report per file per minute: a library mapped by every worker of
    // a service is one finding (the counters keep the total).
    let now = bpf_ktime_get_ns();
    if reported != 0 && now.wrapping_sub(reported) < MAP_REPORT_EVERY_NS {
        return rc;
    }
    let v = MapSeen {
        ctime_sec: cs,
        ctime_nsec: cn,
        classes,
        reported_ns: now,
    };
    let _ = EXECMAP_SEEN.insert(&key, &v, 0);
    let mut entry = match EXECPOL_EVENTS.reserve::<ExecPolRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::EXECPOL);
            bump(counter::RING_FULL);
            return rc;
        }
    };
    let raw: *mut ExecPolRaw = entry.as_mut_ptr();
    crate::zero::zero(raw);
    fill_head(raw, task);
    (*raw).kind = kind::MAP;
    (*raw).tier = tv;
    (*raw).classes = classes;
    (*raw).action = act;
    (*raw).file_mode = u32::from(peek_u16(inode.add(off!(INODE_I_MODE_OFFSET))));
    if let Some(o) = off_opt!(INODE_I_UID_OFFSET) {
        (*raw).file_uid = peek_u32(inode.add(o & 0xffff));
    }
    // A report from the cache walks the file now (once a minute at most):
    // the per-CPU buffer it was copied from held whatever this CPU walked
    // last (lot 322).
    if cached {
        *walked = Some(wk);
        let _ = nn_map_classify(file as u64, u64::from(wk.tid), wk.start_ns);
    }
    if let Some(sc) = EXECMAP_SCRATCH.get_ptr(&wk) {
        let _ = generated::bpf_probe_read_kernel(
            &mut (*raw).exe as *mut ExeIdentityRaw as *mut c_void,
            core::mem::size_of::<ExeIdentityRaw>() as u32,
            sc as *const c_void,
        );
    }
    (*raw).exe.dev = key.dev;
    (*raw).exe.ino = key.ino;
    entry.submit(0);
    rc
}

/// The classes of a file mapped executable: its walk into the mapping
/// task's own entry (`tid`, `start`; made here), then lab PR 223's
/// classification. A global function (integer arguments): checked once.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_map_classify(file: u64, tid: u64, start: u64) -> u64 {
    unsafe { u64::from(map_classify(file as *const u8, tid, start)) }
}

/// [`nn_map_classify`]'s bit: no walk could be made (the per-task map full):
/// the classes are the fail-closed `tmp`, `var_tmp`, `home`, not cached.
const MAP_WALK_LOST: u32 = 1 << 31;

#[inline(always)]
unsafe fn map_classify(file: *const u8, tid: u64, start: u64) -> u32 {
    let s = match crate::task_scratch::make(&EXECMAP_SCRATCH, &crate::task_scratch::key(tid, start)) {
        Some(p) => p,
        // The review of #546 (F4, F5): counted, and classed as a file the
        // walk cannot place (it was class 0: let through, uncounted).
        None => {
            bump(counter::LOST);
            return MAP_WALK_LOST | class::TMP | class::VAR_TMP | class::HOME;
        }
    };
    let inode = peek_u64(file.add(off!(FILE_F_INODE_OFFSET))) as *const u8;
    let sb = peek_u64(inode.add(off!(INODE_I_SB_OFFSET))) as *const u8;
    let magic = peek_u64(sb.add(off!(SUPER_BLOCK_S_MAGIC_OFFSET)));
    let dentry =
        peek_u64(file.add(off!(FILE_F_PATH_OFFSET) + off!(PATH_DENTRY_OFFSET))) as *const u8;
    let mut fl = exe_flags::KNOWN;
    if magic == TMPFS_MAGIC || magic == HUGETLBFS_MAGIC || magic == RAMFS_MAGIC {
        fl |= exe_flags::TMPFS;
    }
    let name = peek_u64(dentry.add(off!(DENTRY_D_NAME_OFFSET) + off!(QSTR_NAME_OFFSET))) as *const u8;
    if peek_u64(name) & MEMFD_MASK == MEMFD_PREFIX {
        fl |= exe_flags::MEMFD;
    }
    if let Some(o) = off_opt!(INODE_I_NLINK_OFFSET) {
        if peek_u32(inode.add(o & 0xffff)) == 0 {
            fl |= exe_flags::DELETED;
        }
    }
    let task_root = crate::exec_lsm::task_root_of(bpf_get_current_task() as *const u8);
    let key = inode_key(inode);
    (*s).dev = key.dev;
    (*s).ino = key.ino;
    (*s).pass = 0;
    (*s)._pad = 0;
    (*s).flags = fl | (crate::exec_lsm::exe_walk(s, dentry, task_root) as u32);
    crate::execq::classify(s, dentry, (*s).flags)
}
