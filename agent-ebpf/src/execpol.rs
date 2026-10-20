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
//!   environment stash of [`execpol_env_execve`] is judged too.
//! - [`execpol_env_execve`] / [`execpol_env_execveat`] (`sys_enter_*`
//!   tracepoints): a bounded prefix of the new environment, the loader
//!   variables and the history tricks only ([`EnvStashRaw`]).
//! - [`execmap_check`] (LSM `mmap_file`): an executable mapping of a file
//!   in a class, by the caller's tier → `-EACCES` or a report.
//!
//! The exec's point of no return is past every one of these hooks: a deny
//! is the syscall's error, the caller keeps running its old image.
use aya_ebpf::{
    cty::c_void,
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_task,
        bpf_get_current_uid_gid, bpf_ktime_get_ns, gen,
    },
    macros::{lsm, map, tracepoint},
    maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::{LsmContext, TracePointContext},
    EbpfContext,
};
use northnarrow_common::wire::exe::{exe_flags, ExeIdentityRaw};
use northnarrow_common::wire::execpol::{
    action, conf_slot, counter, env_flags, flags, image_role, kind, mode, slice_slot, tier,
    tier_sig, EnvStashRaw, ExecPolRaw, MapSeen, ENV_AUDIT_LEN, ENV_HIST_LEN, ENV_LIBPATH_LEN,
    ENV_PREFIX_LEN, ENV_PRELOAD_LEN, ENV_SCAN_MAX, ENV_TUNABLES_LEN, MAP_REPORT_EVERY_NS,
};
use northnarrow_common::wire::execq::{class, ExecqKey};

use crate::btf_offsets::{
    DENTRY_D_NAME_OFFSET, FILE_F_INODE_OFFSET, FILE_F_PATH_OFFSET, FS_STRUCT_ROOT_OFFSET,
    INODE_I_CTIME_NSEC_OFFSET, INODE_I_CTIME_SEC_OFFSET, INODE_I_INO_OFFSET, INODE_I_MODE_OFFSET,
    INODE_I_NLINK_OFFSET, INODE_I_SB_OFFSET, INODE_I_UID_OFFSET, MM_STRUCT_EXE_FILE_OFFSET,
    PATH_DENTRY_OFFSET, QSTR_NAME_OFFSET, SIGNAL_STRUCT_TTY_OFFSET, SUPER_BLOCK_S_DEV_OFFSET,
    SUPER_BLOCK_S_MAGIC_OFFSET, TASK_STRUCT_FS_OFFSET, TASK_STRUCT_LOGINUID_OFFSET,
    TASK_STRUCT_MM_OFFSET, TASK_STRUCT_REAL_PARENT_OFFSET, TASK_STRUCT_SIGNAL_OFFSET,
    TASK_STRUCT_START_TIME_OFFSET, TASK_STRUCT_TGID_OFFSET, TP_SYS_ENTER_EXECVEAT_ENVP_OFFSET,
    TP_SYS_ENTER_EXECVE_ENVP_OFFSET,
};

/// `EACCES`.
const EACCES: i32 = 13;
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
/// The environment findings of an exec in progress, keyed by
/// `task_struct`, from `sys_enter_execve{,at}` to the exec's pass 0.
#[map]
static EXECPOL_ENV: LruHashMap<u64, EnvStashRaw> = LruHashMap::with_max_entries(1024, 0);
/// Where a stash is built (416 bytes: never on the stack).
#[map]
static EXECPOL_ENV_SCRATCH: PerCpuArray<EnvStashRaw> = PerCpuArray::with_max_entries(1, 0);
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
/// sensor's.
#[map]
pub(crate) static EXECMAP_SCRATCH: PerCpuArray<ExeIdentityRaw> = PerCpuArray::with_max_entries(1, 0);

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
    // Level 1: the top-level slice the caller's cgroup is under.
    let cg1 = gen::bpf_get_current_ancestor_cgroup_id(1);
    if cg1 != 0 && cg1 == sys {
        return tier::SERVICE | sig | tier_sig::SYSTEM_SLICE;
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
/// exec'ing `task_struct`). Returns the pass's verdict.
#[inline(always)]
pub(crate) unsafe fn on_pass(
    s: *const ExeIdentityRaw,
    inode: *const u8,
    dentry: *const u8,
    task: u64,
    pass: u8,
) -> i32 {
    let m = conf(conf_slot::MODE);
    let q = crate::execq::armed();
    if m == mode::OFF && !q {
        return 0;
    }
    let classes = crate::execq::nn_execq_classify(dentry as u64, (*s).flags as u64) as u32;
    if m == mode::OFF {
        // Lab PR 223 alone: every class the guard holds.
        return crate::execq::note_pass(s, inode, task, pass, classes);
    }
    let env = if pass == 0 {
        EXECPOL_ENV.get_ptr(&task)
    } else {
        None
    };
    if classes == 0 && env.is_none() {
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
    let mut env_act = 0u32;
    let mut mode_bits = 0u32;
    if let Some(e) = env {
        let ef = (*e).flags;
        let tb = 1u64 << t;
        mode_bits = u32::from(peek_u16(inode.add(off!(INODE_I_MODE_OFFSET))));
        let setid = mode_bits & 0o6000 != 0;
        // A set-id target runs with `AT_SECURE`: the loader ignores these
        // entries itself; recorded, not denied (no duplicate of the kernel).
        if ef & env_flags::DENYABLE != 0 && !setid {
            let root = tv & tier_sig::ROOT != 0;
            if conf(conf_slot::ENV_DENY) & tb != 0
                || (root && conf(conf_slot::ENV_DENY_ROOT) & tb != 0)
            {
                if m == mode::ENFORCE {
                    env_act |= action::DENY;
                    bump(counter::ENV_DENIED);
                } else {
                    env_act |= action::WOULD_DENY;
                }
            }
        }
        let reportable = ef
            & (env_flags::DENYABLE | env_flags::LIBPATH_STAGING | env_flags::HISTORY)
            != 0
            || (setid && ef & env_flags::GLIBC_TUNABLES != 0);
        if conf(conf_slot::ENV_RECORD) & tb != 0 && reportable {
            env_act |= action::RECORD;
        }
        if env_act != 0 {
            bump(counter::ENV_RECORDED);
        }
        if ef & env_flags::TRUNCATED != 0 {
            bump(counter::ENV_TRUNCATED);
        }
    }
    if act & (action::DENY | action::WOULD_DENY) != 0 || env_act != 0 {
        if mode_bits == 0 {
            mode_bits = u32::from(peek_u16(inode.add(off!(INODE_I_MODE_OFFSET))));
        }
        report_exec(s, inode, t_ptr, t | sig, classes, act, env_act, env, mode_bits);
    }
    if pass == 0 {
        let _ = EXECPOL_ENV.remove(&task);
    }
    if (act | env_act) & action::DENY != 0 {
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
    (*raw).cgroup_id = gen::bpf_get_current_cgroup_id();
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
    if let Some(e) = env {
        (*raw).env_flags = (*e).flags;
        (*raw).env_count = (*e).count;
        (*raw).tunables_len = (*e).tunables_len;
        let _ = gen::bpf_probe_read_kernel(
            (*raw).preload.as_mut_ptr() as *mut c_void,
            (ENV_PRELOAD_LEN + ENV_AUDIT_LEN + ENV_TUNABLES_LEN + ENV_LIBPATH_LEN + ENV_HIST_LEN)
                as u32,
            (*e).preload.as_ptr() as *const c_void,
        );
    }
    let _ = gen::bpf_probe_read_kernel(
        &mut (*raw).exe as *mut ExeIdentityRaw as *mut c_void,
        core::mem::size_of::<ExeIdentityRaw>() as u32,
        s as *const c_void,
    );
    entry.submit(0);
}

// ── the new environment, at the syscall's entry ─────────────────────

#[tracepoint]
pub fn execpol_env_execve(ctx: TracePointContext) -> u32 {
    let envp = unsafe { ctx.read_at::<u64>(off!(TP_SYS_ENTER_EXECVE_ENVP_OFFSET)) }.unwrap_or(0);
    unsafe { stash_env(envp) };
    0
}

#[tracepoint]
pub fn execpol_env_execveat(ctx: TracePointContext) -> u32 {
    let envp = unsafe { ctx.read_at::<u64>(off!(TP_SYS_ENTER_EXECVEAT_ENVP_OFFSET)) }.unwrap_or(0);
    unsafe { stash_env(envp) };
    0
}

#[inline(always)]
unsafe fn stash_env(envp: u64) {
    if conf(conf_slot::MODE) == mode::OFF || conf(conf_slot::FLAGS) & flags::ENV_SCAN == 0 {
        return;
    }
    let task = bpf_get_current_task();
    let found = nn_env_scan(envp);
    if found == 0 {
        // Nothing to judge; a failed exec's stash is not this one's.
        let _ = EXECPOL_ENV.remove(&task);
        return;
    }
    if let Some(e) = EXECPOL_ENV_SCRATCH.get_ptr(0) {
        let _ = EXECPOL_ENV.insert(&task, &*e, 0);
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

/// Read the environment array `envp` (user memory of the caller, its old
/// image) into the per-CPU stash: at most [`ENV_SCAN_MAX`] variables, 24
/// bytes of each compared, the values of the loader variables captured.
/// Returns the findings ([`env_flags`]). A global function: the verifier
/// checks its loop once.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_env_scan(envp: u64) -> u64 {
    unsafe { u64::from(env_scan(envp)) }
}

#[inline(always)]
unsafe fn env_scan(envp: u64) -> u32 {
    let e = match EXECPOL_ENV_SCRATCH.get_ptr_mut(0) {
        Some(p) => p,
        None => return 0,
    };
    // Findings go to the stash's memory, not to a register: the verifier
    // then sees the same state at the loop head whatever matched, and the
    // 64 iterations stay linear (5.15 rule: no state explosion in loops).
    (*e).flags = 0;
    (*e).count = 0;
    (*e).tunables_len = 0;
    (*e).preload[0] = 0;
    (*e).audit[0] = 0;
    (*e).tunables[0] = 0;
    (*e).libpath[0] = 0;
    (*e).hist[0] = 0;
    if envp == 0 {
        return 0;
    }
    let mut i = 0usize;
    while i < ENV_SCAN_MAX {
        let mut ptr = 0u64;
        if gen::bpf_probe_read_user(
            &mut ptr as *mut u64 as *mut c_void,
            8,
            (envp + (i as u64) * 8) as *const c_void,
        ) != 0
        {
            (*e).flags |= env_flags::UNREADABLE;
            break;
        }
        if ptr == 0 {
            break;
        }
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
        let _ = gen::bpf_probe_read_user_str(
            wp as *mut c_void,
            ENV_PREFIX_LEN as u32,
            ptr as *const c_void,
        );
        let w = buf.assume_init();
        scan_one(e, ptr, w[0], w[1], w[2]);
        i += 1;
    }
    (*e).count = i as u32;
    if i == ENV_SCAN_MAX {
        // Was there a 65th?
        let mut ptr = 0u64;
        let _ = gen::bpf_probe_read_user(
            &mut ptr as *mut u64 as *mut c_void,
            8,
            (envp + (ENV_SCAN_MAX as u64) * 8) as *const c_void,
        );
        if ptr != 0 {
            (*e).flags |= env_flags::TRUNCATED;
        }
    }
    if (*e).flags & env_flags::LD_PRELOAD != 0 && nn_list_staging(0) != 0 {
        (*e).flags |= env_flags::PRELOAD_STAGING;
    }
    if (*e).flags & env_flags::LD_AUDIT != 0 && nn_list_staging(1) != 0 {
        (*e).flags |= env_flags::AUDIT_STAGING;
    }
    if (*e).flags & env_flags::LD_LIBRARY_PATH != 0 && nn_list_staging(2) != 0 {
        (*e).flags |= env_flags::LIBPATH_STAGING;
    }
    (*e).flags
}

/// One variable (`ptr`, its first 24 bytes in `w0..w2`): a finding into the
/// stash, and the value of a loader variable captured.
#[inline(always)]
unsafe fn scan_one(e: *mut EnvStashRaw, ptr: u64, w0: u64, w1: u64, w2: u64) {
    if w0 == W_LD_PRELO && w1 & M3 == W_AD_EQ {
        (*e).flags |= env_flags::LD_PRELOAD;
        let len = gen::bpf_probe_read_user_str(
            (*e).preload.as_mut_ptr() as *mut c_void,
            ENV_PRELOAD_LEN as u32,
            (ptr + 11) as *const c_void,
        );
        if len >= ENV_PRELOAD_LEN as i64 {
            (*e).flags |= env_flags::VALUE_CUT;
        }
    } else if w0 == W_LD_AUDIT && w1 & M1 == u64::from(b'=') {
        (*e).flags |= env_flags::LD_AUDIT;
        let len = gen::bpf_probe_read_user_str(
            (*e).audit.as_mut_ptr() as *mut c_void,
            ENV_AUDIT_LEN as u32,
            (ptr + 9) as *const c_void,
        );
        if len >= ENV_AUDIT_LEN as i64 {
            (*e).flags |= env_flags::VALUE_CUT;
        }
    } else if w0 == W_LD_LIBRA && w1 == W_RY_PATH {
        (*e).flags |= env_flags::LD_LIBRARY_PATH;
        let len = gen::bpf_probe_read_user_str(
            (*e).libpath.as_mut_ptr() as *mut c_void,
            ENV_LIBPATH_LEN as u32,
            (ptr + 16) as *const c_void,
        );
        if len >= ENV_LIBPATH_LEN as i64 {
            (*e).flags |= env_flags::VALUE_CUT;
        }
    } else if w0 == W_GLIBC_TU && w1 & M7 == W_NABLES {
        (*e).flags |= env_flags::GLIBC_TUNABLES;
        let len = gen::bpf_probe_read_user_str(
            (*e).tunables.as_mut_ptr() as *mut c_void,
            ENV_TUNABLES_LEN as u32,
            (ptr + 15) as *const c_void,
        );
        (*e).tunables_len = if len > 0 { (len - 1) as u32 } else { 0 };
    } else if w0 == W_HISTFILE && w1 & M1 == u64::from(b'=') {
        (*e).flags |= env_flags::HISTFILE;
        let _ = gen::bpf_probe_read_user_str(
            (*e).hist.as_mut_ptr() as *mut c_void,
            ENV_HIST_LEN as u32,
            (ptr + 9) as *const c_void,
        );
        // "HISTFILE=" then "/dev/null" or nothing.
        let v = (w1 >> 8) | (w2 << 56);
        if v & M1 == 0 || (v == W_DEV_NUL && (w2 >> 8) & 0xffff == 0x6c) {
            (*e).flags |= env_flags::HISTFILE_NULL;
        }
    } else if w0 == W_HISTFILE && w1 & M5 == W_SIZE_EQ {
        if (w1 >> 40) & 0xffff == 0x0030 {
            (*e).flags |= env_flags::HISTFILESIZE_ZERO;
        }
    } else if w0 == W_HISTSIZE && w1 & M3 == W_EQ_ZERO {
        (*e).flags |= env_flags::HISTSIZE_ZERO;
    } else if w0 == W_HISTCONT && w1 == W_ROL_IGNO {
        (*e).flags |= env_flags::HISTCONTROL_IGNORE;
    }
}

/// "/tmp/", "/var/tmp/", "/dev/shm/", "/proc/", "/dev/fd/" — as eight
/// little-endian bytes and the mask of their length (the last three are
/// longer than eight: their ninth byte is checked apart).
const P_TMP: u64 = u64::from_le_bytes(*b"/tmp/\0\0\0");
const P_VAR_TMP: u64 = u64::from_le_bytes(*b"/var/tmp");
const P_DEV_SHM: u64 = u64::from_le_bytes(*b"/dev/shm");
const P_PROC: u64 = u64::from_le_bytes(*b"/proc/\0\0");
const P_DEV_FD: u64 = u64::from_le_bytes(*b"/dev/fd/");
const M6: u64 = 0xffff_ffff_ffff;

/// Whether an entry of the colon- (or, for `LD_PRELOAD`, space-) separated
/// list captured in the stash (`which`: 0 preload, 1 audit, 2 library
/// path) starts with a staging prefix ([`STAGING_PREFIXES`](northnarrow_common::wire::execpol::STAGING_PREFIXES)).
/// A global function: its byte loop is checked once.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_list_staging(which: u64) -> u64 {
    unsafe {
        let e = match EXECPOL_ENV_SCRATCH.get_ptr(0) {
            Some(p) => p,
            None => return 0,
        };
        let (base, len) = match which {
            0 => ((*e).preload.as_ptr(), ENV_PRELOAD_LEN),
            1 => ((*e).audit.as_ptr(), ENV_AUDIT_LEN),
            _ => ((*e).libpath.as_ptr(), ENV_LIBPATH_LEN),
        };
        u64::from(list_staging(base, len))
    }
}

#[inline(always)]
unsafe fn list_staging(base: *const u8, len: usize) -> bool {
    let mut start = true;
    let mut i = 0usize;
    while i < ENV_PRELOAD_LEN {
        if i >= len {
            break;
        }
        let b = *base.add(i);
        if b == 0 {
            break;
        }
        if b == b':' || b == b' ' {
            start = true;
        } else {
            if start && b == b'/' && i + 9 <= len {
                let mut w = 0u64;
                let mut nine = 0u8;
                let _ = gen::bpf_probe_read_kernel(
                    &mut w as *mut u64 as *mut c_void,
                    8,
                    base.add(i) as *const c_void,
                );
                let _ = gen::bpf_probe_read_kernel(
                    &mut nine as *mut u8 as *mut c_void,
                    1,
                    base.add(i + 8) as *const c_void,
                );
                if w & M5 == P_TMP
                    || w & M6 == P_PROC
                    || w == P_DEV_FD
                    || ((w == P_VAR_TMP || w == P_DEV_SHM) && nine == b'/')
                {
                    return true;
                }
            }
            start = false;
        }
        i += 1;
    }
    false
}

// ── executable mappings ─────────────────────────────────────────────

/// Argument `i` of the hook, read from the context without the verifier's
/// BTF typing (a scalar).
#[inline(always)]
unsafe fn raw_arg(ctx: &LsmContext, i: usize) -> u64 {
    let args = ctx.as_ptr() as *const u64;
    let mut v = 0u64;
    let _ = gen::bpf_probe_read_kernel(
        &mut v as *mut u64 as *mut c_void,
        8,
        args.add(i) as *const c_void,
    );
    v
}

#[lsm(hook = "mmap_file")]
pub fn execmap_check(ctx: LsmContext) -> i32 {
    unsafe { try_execmap(&ctx) }
}

#[inline(always)]
unsafe fn try_execmap(ctx: &LsmContext) -> i32 {
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
    let task = bpf_get_current_task() as *const u8;
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
    if !cached {
        classes = nn_map_classify(file as u64) as u32;
        let v = MapSeen {
            ctime_sec: cs,
            ctime_nsec: cn,
            classes,
            reported_ns: 0,
        };
        let _ = EXECMAP_SEEN.insert(&key, &v, 0);
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
    if let Some(sc) = EXECMAP_SCRATCH.get_ptr(0) {
        let _ = gen::bpf_probe_read_kernel(
            &mut (*raw).exe as *mut ExeIdentityRaw as *mut c_void,
            core::mem::size_of::<ExeIdentityRaw>() as u32,
            sc as *const c_void,
        );
    }
    // The cached path is the one walked at first sight; a report from the
    // cache says which inode (the walk is not redone).
    (*raw).exe.dev = key.dev;
    (*raw).exe.ino = key.ino;
    entry.submit(0);
    rc
}

/// The classes of a file mapped executable: its walk into the mapping
/// check's own scratch, then lab PR 223's classification. A global
/// function (integer argument): checked once.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_map_classify(file: u64) -> u64 {
    unsafe { u64::from(map_classify(file as *const u8)) }
}

#[inline(always)]
unsafe fn map_classify(file: *const u8) -> u32 {
    let s = match EXECMAP_SCRATCH.get_ptr_mut(0) {
        Some(p) => p,
        None => return 0,
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
    let task = bpf_get_current_task() as *const u8;
    let mut task_root: *const u8 = core::ptr::null();
    if let Some(o_fs) = off_opt!(TASK_STRUCT_FS_OFFSET) {
        if let Some(o_root) = off_opt!(FS_STRUCT_ROOT_OFFSET) {
            let fs = peek_u64(task.add(o_fs & 0xffff)) as *const u8;
            task_root = peek_u64(fs.add((o_root & 0xffff) + off!(PATH_DENTRY_OFFSET))) as *const u8;
        }
    }
    let key = inode_key(inode);
    (*s).dev = key.dev;
    (*s).ino = key.ino;
    (*s).pass = 0;
    (*s)._pad = 0;
    (*s).flags = fl | (crate::exec_lsm::exe_walk(s, dentry, task_root) as u32);
    crate::execq::classify(s, dentry, (*s).flags)
}
