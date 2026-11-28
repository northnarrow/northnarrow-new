//! Lot 2.3a (stage S2): the trusted-installer window per process tree, the
//! kernel side (the design: `docs/design/ANTITAMPER_TRUST_MODEL.md`,
//! "Trusted-installer window per process tree"). The decisions are
//! `northnarrow_common::window_tree`'s, tested there.
//!
//! * **The lift.** [`nn_window_lift`] answers `override_active()` for the
//!   calling process: while a tree grant is in force (`FS_GRANT_V2`), the
//!   caller must be a member of its generation ([`nn_tree_member_now`]:
//!   its `TREE_MEMBERS` entry, its start, the window open on
//!   `CLOCK_BOOTTIME` with a fresh heartbeat, no io_uring worker, not
//!   traced, no seccomp mode, the initial user and pid namespaces). A
//!   member that fails the last three leaves the tree, signed. While no
//!   tree grant is in force, the host-wide grant (`FS_GRANT`) answers as
//!   before: the flows use it until lots 2.3b and 2.4 move them (declared).
//! * **The members.** [`tree_fork`] (`sched_process_fork`, BTF)
//!   writes a member's child's entry; [`tree_exit`] (the thread
//!   group's death) and [`tree_task_free`] (the leader's free)
//!   remove an entry, each only for its own process (its start). The
//!   root's death, or its eviction, closes the window in the kernel at
//!   once ([`TREE_CLOSED`]).
//!   - The fork span. `copy_process` calls `task_alloc` before the child
//!     has its pid (`alloc_pid`) and its start (`start_boottime`), and puts
//!     it in the pid hash (`attach_pid`) before `sched_process_fork`, so
//!     an outsider could name the child between the two (a ptrace attach,
//!     a `/proc/<pid>/mem` open — whose descriptor keeps the child's mm, a
//!     vfork or `posix_spawn` child's being the member's own). So
//!     [`tree_task_alloc`] makes a member's child a member at once,
//!     synchronously, by its `task_struct` ([`TREE_PENDING`]: the
//!     generation, the start unknown yet), and [`tree_fork`] confirms it
//!     under its tgid with its start before `wake_up_new_task`. Until then
//!     the guards of D7 ([`nn_tree_target_guarded`]) also protect a task
//!     still in `TASK_NEW`, and any child of a member (a vfork child a full
//!     map left outside, a `CLONE_VM` child evicted before its exec).
//!     A member's fork after the window closed writes nothing.
//!   - An exec by a thread that is not the leader takes the leader's pid
//!     and its start (`de_thread` copies `start_boottime`), so the pair
//!     stays the process's; every test reads the group leader's start.
//! * **The exec and mapping rule (D4).** A member that executes a file, or
//!   maps one (or anonymous memory) executable, that fails the role's trust
//!   test (`exec_marks::code_verdict`, D10) or lies in a directory writable
//!   by others or sticky, leaves the tree, signed: each pass of an exec at
//!   `bprm_check_security` (a `#!` script and its interpreter, a
//!   `binfmt_misc` handler), the final file at `bprm_committed_creds`, the
//!   new environment at `sched_process_exec` (it is laid out only by then:
//!   `create_elf_tables` runs after `begin_new_exec`), and every executable
//!   `mmap` or `mprotect`.
//! * **The members protected (D7).** While the window is open, an outsider
//!   (PID 1 included) is refused a ptrace check of a member, in either mode
//!   ([`tree_ptrace`]: debuggers, `/proc/<pid>/mem`, `fd`,
//!   `environ`, `maps`, `process_vm_*`, `pidfd_getfd`, `kcmp`, a perf event
//!   on its pid), and a descriptor of an io_uring ring or of a protected
//!   inode crosses no boundary ([`tree_fd_receive`]). Its signals
//!   are `task_kill`'s.
//!
//! Every program returns at its first map lookup on a host with no tree
//! window, the common case. What `override_active()` reaches
//! ([`nn_window_lift`], [`nn_tree_member_now`] and what they call) uses no
//! helper the `cgroup/sysctl` program type lacks on 5.15 (no
//! `bpf_get_current_pid_tgid`: the tgid is read from the task).

use aya_ebpf::{
    cty::{c_int, c_void},
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_task, bpf_ktime_get_boot_ns, bpf_ktime_get_ns,
        bpf_probe_read_kernel, generated,
    },
    macros::{btf_tracepoint, lsm, map},
    maps::{Array, PerCpuArray},
    programs::{BtfTracePointContext, LsmContext},
};
use northnarrow_common::exec_marks::CODE_ANONYMOUS;
use northnarrow_common::window_tree::{
    caller_state_verdict, child_joins, denial_class, entry_is_process, env_head_dangerous, exec_verdict,
    grant_in_force, in_tree_span, is_root, window_closed, CallerFacts, CLOSE_ROOT_EVICTED, CLOSE_ROOT_EXIT,
    CODE_UNSAFE_DIR, ENV_HEAD, ENV_MAX_BYTES, ENV_MAX_VARS, ENV_VAR_MAX, EVICT_ENV, EVICT_EXEC,
    EVICT_FULL, EVICT_MAP, EVICT_TRACED, MEMBER_LIFT, MEMBER_NONE,
};
use northnarrow_common::wire::{
    start_ticks, FsGrantV2, InodeKey, TreeMember, DENIAL_WINDOW_EXEC_EVICTED,
    DENIAL_WINDOW_NONE, DENIAL_WINDOW_OUTSIDER, FS_OP_FD_RECEIVE, FS_OP_PTRACE,
    WINDOW_EVENT_CLOSE, WINDOW_EVENT_EVICTION, WINDOW_EVENT_OUTSIDER_REFUSED,
};

use crate::btf_offsets::{
    CRED_USER_NS_OFFSET, DENTRY_D_INODE_OFFSET, DENTRY_D_NAME_OFFSET, DENTRY_D_PARENT_OFFSET,
    FILE_F_INODE_OFFSET, FILE_F_PATH_OFFSET, INODE_I_MODE_OFFSET, LINUX_BINPRM_FILE_OFFSET,
    MM_STRUCT_ENV_END_OFFSET, MM_STRUCT_ENV_START_OFFSET, NSPROXY_PID_NS_FOR_CHILDREN_OFFSET,
    PATH_DENTRY_OFFSET, PF_IO_WORKER, PID_NAMESPACE_INUM_OFFSET, QSTR_NAME_OFFSET,
    SIGNAL_STRUCT_LIVE_OFFSET, TASK_STRUCT_CRED_OFFSET, TASK_STRUCT_FLAGS_OFFSET,
    TASK_STRUCT_GROUP_LEADER_OFFSET, TASK_STRUCT_MM_OFFSET, TASK_STRUCT_NSPROXY_OFFSET,
    TASK_STRUCT_PTRACE_OFFSET, TASK_STRUCT_REAL_PARENT_OFFSET, TASK_STRUCT_SECCOMP_MODE_OFFSET,
    TASK_STRUCT_SIGNAL_OFFSET, TASK_STRUCT_START_BOOTTIME_OFFSET, TASK_STRUCT_STATE_OFFSET,
    TASK_STRUCT_TGID_OFFSET, USER_NAMESPACE_INUM_OFFSET,
    VM_AREA_STRUCT_VM_FILE_OFFSET, VM_AREA_STRUCT_VM_FLAGS_OFFSET,
};
use crate::window_maps::{emit_window_event, FS_GRANT_V2, TREE_CGROUP_FILES, TREE_MEMBERS, TREE_PENDING};

const EPERM: c_int = 1;
/// `PROT_EXEC`, `VM_EXEC`.
const PROT_EXEC: u64 = 0x4;
const VM_EXEC: u64 = 0x4;
/// `PTRACE_MODE_ATTACH`, `PTRACE_MODE_NOAUDIT` (include/linux/ptrace.h).
const PTRACE_MODE_ATTACH: u32 = 0x02;
const PTRACE_MODE_NOAUDIT: u32 = 0x04;
/// `PROC_USER_INIT_INO`, `PROC_PID_INIT_INO` (include/linux/proc_ns.h).
const PROC_USER_INIT_INO: u32 = 0xEFFF_FFFD;
const PROC_PID_INIT_INO: u32 = 0xEFFF_FFFC;
/// "[io_urin" and "g]\0" as little-endian words: the name of an io_uring
/// ring's anonymous file (`anon_inode_getfile_secure("[io_uring]", …)`).
const IO_URING_LO: u64 = u64::from_le_bytes(*b"[io_urin");
const IO_URING_HI: u64 = 0x005d_67;
const IO_URING_HI_MASK: u64 = 0xff_ffff;

/// Slot 0: `[session, generation]` of the window the kernel closed (its
/// root's thread group died, or the root left the tree). Written by these
/// programs only; the agent empties it at its start. Pinned by name with
/// the window's other maps.
#[map]
pub static TREE_CLOSED: Array<[u64; 2]> = Array::pinned(1, 0);

/// `SHM_EXEC` (include/uapi/linux/shm.h).
const SHM_EXEC: u64 = 0o100000;

/// `CLONE_THREAD` (include/uapi/linux/sched.h).
const CLONE_THREAD: u64 = 0x0001_0000;

/// A variable's length is read here when its head did not hold it (the
/// helper copies up to the variable's end, the length is all that is used:
/// another program on this CPU writing it meanwhile changes nothing).
#[map]
static TREE_ENV_SCRATCH: PerCpuArray<[u8; ENV_VAR_MAX as usize]> = PerCpuArray::with_max_entries(1, 0);

// ── reads ───────────────────────────────────────────────────────────────

/// A global function's answer as the caller's code may branch on it: read
/// back through a volatile stack slot. LLVM knows such a function returns 0
/// or 1 and folded arithmetic on the raw value that the verifier, which
/// sees an unknown scalar, could not bound (7.0: `mount_guard`'s exit value
/// "should have been in [-4095, 0]"); a volatile load's value has no range
/// LLVM may assume, so the caller compares it. The agent's one barrier,
/// [`crate::opaque::opaque`] (`xtask/tests/ebpf_barriers.rs`).
#[inline(always)]
pub(crate) fn opaque(v: u64) -> u64 {
    crate::opaque::opaque(v)
}

#[inline(always)]
fn session() -> u32 {
    match crate::task_kill::AGENT_SESSION.get(0) {
        Some(v) => *v,
        None => 0,
    }
}

/// The grant slot, in the map (no copy: every byte of a global
/// function's frame counts in the hooks' 512-byte chains).
#[inline(always)]
fn grant_now() -> Option<&'static FsGrantV2> {
    FS_GRANT_V2.get(0)
}

#[inline(always)]
fn closed(session: u32, generation: u64) -> bool {
    match TREE_CLOSED.get(0) {
        Some(c) => window_closed(c, session, generation),
        None => false,
    }
}

/// The tree window is open in the kernel: its grant in force and not
/// closed by these programs (the heartbeat is `FsGrantV2::active`'s: a
/// window whose agent is gone lifts nothing, and still guards its members).
#[inline(always)]
fn tree_open(g: &FsGrantV2, now: u64, session: u32) -> bool {
    grant_in_force(g, now, session) && !closed(session, g.generation)
}

#[inline(always)]
unsafe fn read_ptr(p: *const u8) -> Option<*const u8> {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        match bpf_probe_read_kernel::<*const u8>(p as *const *const u8) {
            Ok(v) if !v.is_null() => Some(v),
            _ => None,
        }
    }
}

#[inline(always)]
unsafe fn read_u32(p: *const u8) -> Option<u32> {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe { bpf_probe_read_kernel::<u32>(p as *const u32).ok() }
}

#[inline(always)]
unsafe fn read_u64(p: *const u8) -> Option<u64> {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe { bpf_probe_read_kernel::<u64>(p as *const u64).ok() }
}

/// The process's start (`wire::start_ticks` of its group leader's
/// `start_boottime`); `None` when it cannot be read.
#[inline(always)]
unsafe fn process_start(task: *const u8) -> Option<u64> {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let o = off_opt!(TASK_STRUCT_START_BOOTTIME_OFFSET)?;
        let leader = read_ptr(task.add(off!(TASK_STRUCT_GROUP_LEADER_OFFSET)))?;
        Some(start_ticks(read_u64(leader.add(o))?))
    }
}

/// What the per-lift test reads of `task` (`window_tree::CallerFacts`); a
/// field this kernel does not have, or a read that fails, is `read: false`.
/// Each offset is read just before its use (a tuple of the eight offsets
/// took 112 bytes of the step's frame: the hooks' stack chains).
#[inline(always)]
unsafe fn caller_facts(task: *const u8) -> CallerFacts {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let unread = CallerFacts {
            read: false,
            traced: false,
            seccomp_mode: 0,
            ns_initial: false,
        };
        let Some(o) = off_opt!(TASK_STRUCT_PTRACE_OFFSET) else {
            return unread;
        };
        let Some(ptrace) = read_u32(task.add(o)) else {
            return unread;
        };
        let Some(o) = off_opt!(TASK_STRUCT_SECCOMP_MODE_OFFSET) else {
            return unread;
        };
        let Some(seccomp) = read_u32(task.add(o)) else {
            return unread;
        };
        let Some(o) = off_opt!(TASK_STRUCT_CRED_OFFSET) else {
            return unread;
        };
        let Some(cred) = read_ptr(task.add(o)) else {
            return unread;
        };
        let Some(o) = off_opt!(CRED_USER_NS_OFFSET) else {
            return unread;
        };
        let Some(ns) = read_ptr(cred.add(o)) else {
            return unread;
        };
        let Some(o) = off_opt!(USER_NAMESPACE_INUM_OFFSET) else {
            return unread;
        };
        let Some(user) = read_u32(ns.add(o)) else {
            return unread;
        };
        let Some(o) = off_opt!(TASK_STRUCT_NSPROXY_OFFSET) else {
            return unread;
        };
        let Some(nsp) = read_ptr(task.add(o)) else {
            return unread;
        };
        let Some(o) = off_opt!(NSPROXY_PID_NS_FOR_CHILDREN_OFFSET) else {
            return unread;
        };
        let Some(pns) = read_ptr(nsp.add(o)) else {
            return unread;
        };
        let Some(o) = off_opt!(PID_NAMESPACE_INUM_OFFSET) else {
            return unread;
        };
        let Some(pid) = read_u32(pns.add(o)) else {
            return unread;
        };
        CallerFacts {
            read: true,
            traced: ptrace != 0,
            seccomp_mode: seccomp,
            ns_initial: user == PROC_USER_INIT_INO && pid == PROC_PID_INIT_INO,
        }
    }
}

// ── records ─────────────────────────────────────────────────────────────

#[inline(always)]
fn record(kind: u8, class: u8, operation: u8, generation: u64, tgid: u32, start: u64, detail: u64) {
    emit_window_event(kind, class, operation, generation, tgid, start, detail);
}

/// The kernel closes the window `g` (`why`: `CLOSE_ROOT_*`), signed.
#[inline(always)]
fn close(g: &FsGrantV2, why: u64, tgid: u32, start: u64) {
    if let Some(p) = TREE_CLOSED.get_ptr_mut(0) {
        // SAFETY: slot 0 of this program's array; a store of two words.
        unsafe {
            (*p)[0] = u64::from(g.nonce);
            (*p)[1] = g.generation;
        }
    }
    record(WINDOW_EVENT_CLOSE, DENIAL_WINDOW_NONE, 0, g.generation, tgid, start, why);
}

/// Member `tgid` (start `start`) leaves the tree (`reason`: `EVICT_*`;
/// `code` the file's verdict, for an exec or a mapping), signed; the
/// root's eviction closes the window.
#[inline(always)]
fn evict(g: &FsGrantV2, tgid: u32, start: u64, reason: u64, code: u64) {
    let _ = TREE_MEMBERS.remove(&tgid);
    record(
        WINDOW_EVENT_EVICTION,
        DENIAL_WINDOW_EXEC_EVICTED,
        0,
        g.generation,
        tgid,
        start,
        reason | (code << 8),
    );
    if is_root(g, tgid, start) {
        close(g, CLOSE_ROOT_EVICTED, tgid, start);
    }
}

// ── the lift ────────────────────────────────────────────────────────────

/// The calling process's membership of the open window, before its own
/// state is read (`FsGrantV2::lifts_for`: its entry, of this generation and
/// for its own start, the window open with a fresh heartbeat, no io_uring
/// worker): `MEMBER_LIFT` or `MEMBER_NONE`. One of the lift test's three
/// steps, each a global function called in turn — never nested — so that
/// the deepest hook that asks (`mount_guard`'s, 320 bytes of its own) stays
/// within the 448-byte gate. The tgid from the task, not
/// `bpf_get_current_pid_tgid`: the `cgroup/sysctl` guard asks
/// `override_active()`, and 5.15 gives that program type no such helper
/// (lot 280a).
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn nn_tree_member_base() -> u64 {
    // SAFETY: the task and what it points to are read through the helper
    // only; the maps are this object's.
    unsafe {
        let task = bpf_get_current_task() as *const u8;
        let Some(tgid) = read_u32(task.add(off!(TASK_STRUCT_TGID_OFFSET))) else {
            return MEMBER_NONE;
        };
        let Some(m) = TREE_MEMBERS.get(&tgid) else {
            return MEMBER_NONE;
        };
        let s = session();
        let Some(g) = grant_now() else {
            return MEMBER_NONE;
        };
        let now = bpf_ktime_get_boot_ns();
        if closed(s, g.generation) {
            return MEMBER_NONE;
        }
        let Some(start) = process_start(task) else {
            return MEMBER_NONE;
        };
        let flags = read_u32(task.add(off!(TASK_STRUCT_FLAGS_OFFSET))).unwrap_or(PF_IO_WORKER);
        if g.lifts_for(Some(m), start, flags & PF_IO_WORKER != 0, now, s) {
            MEMBER_LIFT
        } else {
            MEMBER_NONE
        }
    }
}

/// The calling task's own state at this very call
/// (`window_tree::caller_state_verdict`: not traced, no seccomp mode, the
/// initial user and pid namespaces, every field read): `MEMBER_LIFT` or the
/// reason a member leaves (`EVICT_*`). The lift test's second step.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn nn_tree_caller_state() -> u64 {
    // SAFETY: as above.
    unsafe { caller_state_verdict(caller_facts(bpf_get_current_task() as *const u8)) }
}

/// The calling process leaves the tree (`reason`: `EVICT_*`, `code` the
/// file's verdict for an exec or a mapping), signed; the root's eviction
/// closes the window. The lift test's third step, and the exec and mapping
/// rule's. Always 0.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn nn_tree_evict_current(reason: u64, code: u64) -> u64 {
    // SAFETY: as above.
    unsafe {
        let task = bpf_get_current_task() as *const u8;
        let Some(tgid) = read_u32(task.add(off!(TASK_STRUCT_TGID_OFFSET))) else {
            return 0;
        };
        let Some(g) = grant_now() else {
            return 0;
        };
        evict(g, tgid, process_start(task).unwrap_or(0), reason, code);
        0
    }
}

/// The lift test's three steps in turn (`window_tree::member_verdict`):
/// `MEMBER_LIFT`, `MEMBER_NONE`, or the reason the caller left the tree —
/// its entry is then gone and the eviction signed.
#[inline(always)]
fn member_now() -> u64 {
    let base = nn_tree_member_base();
    if base != MEMBER_LIFT {
        return base;
    }
    let state = nn_tree_caller_state();
    if state >= EVICT_TRACED {
        let _ = nn_tree_evict_current(state, 0);
    }
    state
}

/// [`member_now`] as a global function, for the tree's own programs.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn nn_tree_member_now() -> u64 {
    member_now()
}

/// `override_active()` for the calling process: 1 when the window lifts
/// its refusal. While a tree grant is in force, the tree's answer (the
/// three steps of [`member_now`], each called from here); otherwise the
/// host-wide grant's (`FS_GRANT`, this boot's session and its deadline) —
/// the flows' window until lots 2.3b and 2.4. A tree grant in force keeps
/// the host-wide grant off (one window at a time), closed or not.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn nn_window_lift() -> u64 {
    let s = session();
    if s == 0 {
        return 0;
    }
    if let Some(g) = grant_now() {
        if grant_in_force(g, unsafe { bpf_ktime_get_boot_ns() }, s) {
            return u64::from(member_now() == MEMBER_LIFT);
        }
    }
    match crate::inode_protect::FS_GRANT.get(0) {
        Some(g) => u64::from(g.active(unsafe { bpf_ktime_get_ns() }, s)),
        None => 0,
    }
}

/// Whether the calling process holds an entry of the open window `g` for
/// itself (its start), without judging it: a refusal's class.
#[inline(always)]
unsafe fn caller_is_member(g: &FsGrantV2) -> bool {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
        let Some(m) = TREE_MEMBERS.get(&tgid) else {
            return false;
        };
        if m.generation != g.generation {
            return false;
        }
        matches!(process_start(bpf_get_current_task() as *const u8), Some(s) if entry_is_process(&m, s))
    }
}

/// A refusal's context class (`window_tree::denial_class`) for the calling
/// process; an outsider's refusal while the window is open is also written
/// to the window's ring (`operation`, `detail`: the denial's code and its
/// target), High in the agent. The denial record's `window` byte. A global
/// function: the denial emitter is inlined into every deny program.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn nn_window_class(operation: u64, detail: u64) -> u64 {
    // SAFETY: as above.
    unsafe {
        let s = session();
        let Some(g) = grant_now() else {
            return u64::from(DENIAL_WINDOW_NONE);
        };
        if !tree_open(&g, bpf_ktime_get_boot_ns(), s) {
            return u64::from(DENIAL_WINDOW_NONE);
        }
        let class = denial_class(true, caller_is_member(&g));
        if class == DENIAL_WINDOW_OUTSIDER {
            let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
            let start = process_start(bpf_get_current_task() as *const u8).unwrap_or(0);
            record(
                WINDOW_EVENT_OUTSIDER_REFUSED,
                class,
                operation as u8,
                g.generation,
                tgid,
                start,
                detail,
            );
        }
        u64::from(class)
    }
}

/// Whether the process `tgid` (its leader `task`'s start) holds an entry of
/// generation `generation`.
#[inline(always)]
unsafe fn holds_entry(tgid: u32, task: *const u8, generation: u64) -> bool {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        match TREE_MEMBERS.get(&tgid) {
            Some(m) if m.generation == generation => {
                matches!(process_start(task), Some(st) if entry_is_process(m, st))
            }
            _ => false,
        }
    }
}

/// The fork span's half of the guards (`window_tree::in_tree_span`):
/// `target` (thread group `ttgid`) is a member's child that has no entry
/// yet ([`TREE_PENDING`] of generation `generation`), a task still in
/// `TASK_NEW` (it has not run), or — `parents` — a child of a member (its
/// `real_parent`'s process holds an entry of the window).
#[inline(always)]
unsafe fn target_in_span(target: *const u8, generation: u64, parents: bool) -> bool {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let pending = matches!(TREE_PENDING.get(&(target as u64)), Some(v) if *v == generation);
        let state = match off_opt!(TASK_STRUCT_STATE_OFFSET) {
            Some(o) => read_u32(target.add(o)),
            None => None,
        };
        let parent_member = parents
            && match read_ptr(target.add(off!(TASK_STRUCT_REAL_PARENT_OFFSET))) {
                Some(p) => match read_u32(p.add(off!(TASK_STRUCT_TGID_OFFSET))) {
                    Some(ptgid) => holds_entry(ptgid, p, generation),
                    None => false,
                },
                None => false,
            };
        in_tree_span(pending, state, parent_member)
    }
}

/// Whether `target` (a `task_struct`) is in the open window's tree — a
/// member ([`TREE_MEMBERS`], its own process), or in the fork span
/// ([`target_in_span`]) — and the calling process is outside the tree and
/// outside the agent's family: the members' protection (D7). The caller is
/// judged by the lift test ([`member_now`]: a traced or filtered member is
/// an outsider, and leaves the tree). 1 when the access or the signal must
/// be refused. A global function: `task_kill`, the ptrace guard, the
/// limits' and the cgroup move's guards ask it.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn nn_tree_target_guarded(target: u64) -> u64 {
    // SAFETY: as above.
    unsafe {
        let target = target as *const u8;
        if target.is_null() {
            return 0;
        }
        let Some(g) = grant_now() else {
            return 0;
        };
        let s = session();
        if !tree_open(&g, bpf_ktime_get_boot_ns(), s) {
            return 0;
        }
        let Some(ttgid) = read_u32(target.add(off!(TASK_STRUCT_TGID_OFFSET))) else {
            return 0;
        };
        let caller = (bpf_get_current_pid_tgid() >> 32) as u32;
        if caller == ttgid || crate::task_kill::is_exempt_pid(caller) {
            return 0;
        }
        let generation = g.generation;
        if !holds_entry(ttgid, target, generation) && !target_in_span(target, generation, true) {
            return 0;
        }
        u64::from(member_now() != MEMBER_LIFT)
    }
}

/// Whether `target` (a `task_struct`) is a member of the open window, its
/// own process (no caller is asked): a signal through a file's owner has no
/// sender to tell an outsider by, so while the window is open such a signal
/// to a member is refused whoever raised it (D7; `crate::sigio_guard`). 1
/// when it is. A global function.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn nn_tree_member_target(target: u64) -> u64 {
    // SAFETY: as above.
    unsafe {
        let target = target as *const u8;
        if target.is_null() {
            return 0;
        }
        let Some(ttgid) = read_u32(target.add(off!(TASK_STRUCT_TGID_OFFSET))) else {
            return 0;
        };
        let s = session();
        let Some(g) = grant_now() else {
            return 0;
        };
        if !tree_open(&g, bpf_ktime_get_boot_ns(), s) {
            return 0;
        }
        u64::from(holds_entry(ttgid, target, g.generation) || target_in_span(target, g.generation, false))
    }
}

// ── the members ─────────────────────────────────────────────────────────

/// `task_alloc(struct task_struct *task, unsigned long clone_flags)`, in
/// the forking process, before the child is in the pid hash: a member's
/// new process is a member from here on, by its `task_struct`
/// ([`TREE_PENDING`]), guarded before it can be named; [`tree_fork`]
/// confirms it. A thread joins nothing (its process's entry is its own).
#[lsm(hook = "task_alloc")]
pub fn tree_task_alloc(ctx: LsmContext) -> i32 {
    unsafe {
        let ptgid = (bpf_get_current_pid_tgid() >> 32) as u32;
        if TREE_MEMBERS.get(&ptgid).is_none() {
            return 0;
        }
        let _ = nn_tree_pending(raw_arg(&ctx, 0), raw_arg(&ctx, 1));
    }
    0
}

/// [`tree_task_alloc`]'s write, a global function: the child `child` (a
/// scalar `task_struct` pointer) of a member the window lifts for, unless
/// `clone_flags` makes it a thread. Always 0.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn nn_tree_pending(child: u64, clone_flags: u64) -> u64 {
    if child == 0 || clone_flags & CLONE_THREAD != 0 {
        return 0;
    }
    if nn_tree_member_now() != MEMBER_LIFT {
        return 0;
    }
    if let Some(g) = grant_now() {
        // full: the TASK_NEW and parent guards still hold the span
        let _ = TREE_PENDING.insert(&child, &g.generation, 0);
    }
    0
}

/// `sched_process_fork(struct task_struct *parent, struct task_struct
/// *child)`, in the forking process: a member's new process joins the
/// tree. A thread joins nothing (it shares its process's entry). A full map
/// leaves the child outside, signed (`EVICT_FULL`).
#[btf_tracepoint(function = "sched_process_fork")]
pub fn tree_fork(ctx: BtfTracePointContext) -> i32 {
    unsafe { try_fork(&ctx) };
    0
}

#[inline(always)]
unsafe fn try_fork(ctx: &BtfTracePointContext) {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let ptgid = (bpf_get_current_pid_tgid() >> 32) as u32;
        if TREE_MEMBERS.get(&ptgid).is_none() {
            return;
        }
        let child = ctx.arg::<*const c_void>(1) as *const u8;
        if child.is_null() {
            return;
        }
        // the span ends here: the entry below, or no membership
        let _ = TREE_PENDING.remove(&(child as u64));
        let v = nn_tree_member_now();
        if v != MEMBER_LIFT {
            return;
        }
        let Some(ctgid) = read_u32(child.add(off!(TASK_STRUCT_TGID_OFFSET))) else {
            return;
        };
        if !child_joins(v, ctgid, ptgid) {
            return;
        }
        let Some(g) = grant_now() else {
            return;
        };
        // the child leads its new thread group: its own start
        let Some(o) = off_opt!(TASK_STRUCT_START_BOOTTIME_OFFSET) else {
            return;
        };
        let Some(cs) = read_u64(child.add(o)) else {
            return;
        };
        let entry = TreeMember {
            start_ticks: start_ticks(cs),
            generation: g.generation,
            flags: 0,
            _pad: 0,
        };
        if TREE_MEMBERS.insert(&ctgid, &entry, 0).is_err() {
            record(
                WINDOW_EVENT_EVICTION,
                DENIAL_WINDOW_OUTSIDER,
                0,
                g.generation,
                ctgid,
                entry.start_ticks,
                EVICT_FULL,
            );
        }
    }
}

/// The entry of `tgid` goes when it is `task`'s own process's; the root's
/// end closes the window.
#[inline(always)]
unsafe fn forget(tgid: u32, task: *const u8) {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let Some(m) = TREE_MEMBERS.get(&tgid) else {
            return;
        };
        let Some(start) = process_start(task) else {
            return;
        };
        if !entry_is_process(&m, start) {
            return;
        }
        let _ = TREE_MEMBERS.remove(&tgid);
        if let Some(g) = grant_now() {
            if m.generation == g.generation && is_root(&g, tgid, start) && !closed(g.nonce, g.generation) {
                close(&g, CLOSE_ROOT_EXIT, tgid, start);
            }
        }
    }
}

/// `sched_process_exit(struct task_struct *p)`: the entry leaves with its
/// thread group (the last thread's exit: `signal->live` is 0 by then).
#[btf_tracepoint(function = "sched_process_exit")]
pub fn tree_exit(_ctx: BtfTracePointContext) -> i32 {
    unsafe {
        let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
        if TREE_MEMBERS.get(&tgid).is_none() {
            return 0;
        }
        let task = bpf_get_current_task() as *const u8;
        let (Some(o_sig), Some(o_live)) = (off_opt!(TASK_STRUCT_SIGNAL_OFFSET), off_opt!(SIGNAL_STRUCT_LIVE_OFFSET)) else {
            return 0;
        };
        let Some(sig) = read_ptr(task.add(o_sig)) else {
            return 0;
        };
        if read_u32(sig.add(o_live)) != Some(0) {
            return 0;
        }
        forget(tgid, task);
    }
    0
}

/// `task_free(struct task_struct *task)`: the leader's free removes what
/// the exit left (an entry never outlives its process).
#[lsm(hook = "task_free")]
pub fn tree_task_free(ctx: LsmContext) -> i32 {
    unsafe {
        let task = ctx.arg::<*const c_void>(0) as *const u8;
        if task.is_null() {
            return 0;
        }
        // a fork that failed after `task_alloc` (or a task freed before its
        // confirmation): its span goes, while a tree grant is armed
        if matches!(grant_now(), Some(g) if g.generation != 0) {
            let _ = TREE_PENDING.remove(&(task as u64));
        }
        let Some(tgid) = read_u32(task.add(off!(TASK_STRUCT_TGID_OFFSET))) else {
            return 0;
        };
        if TREE_MEMBERS.get(&tgid).is_none() {
            return 0;
        }
        match read_ptr(task.add(off!(TASK_STRUCT_GROUP_LEADER_OFFSET))) {
            Some(l) if l == task => forget(tgid, task),
            _ => {}
        }
    }
    0
}

// ── the exec and mapping rule ───────────────────────────────────────────

/// The mode of `file`'s directory (`f_path.dentry->d_parent->d_inode`).
#[inline(always)]
unsafe fn dir_mode(file: *const u8) -> Option<u32> {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let dentry = read_ptr(file.add(off!(FILE_F_PATH_OFFSET) + off!(PATH_DENTRY_OFFSET)))?;
        let parent = read_ptr(dentry.add(off!(DENTRY_D_PARENT_OFFSET)))?;
        let inode = read_ptr(parent.add(off!(DENTRY_D_INODE_OFFSET)))?;
        bpf_probe_read_kernel::<u16>(inode.add(off!(INODE_I_MODE_OFFSET)) as *const u16)
            .ok()
            .map(u32::from)
    }
}

/// The exec and mapping rule on `file` (a scalar pointer; 0: anonymous
/// memory) for the calling process, when it is a member the window lifts
/// for: a file that fails it evicts the member (`reason`: `EVICT_EXEC` or
/// `EVICT_MAP`), signed with the verdict. Always 0. A global function.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn nn_tree_judge_file(file: u64, reason: u64) -> u64 {
    // SAFETY: the file and what it points to are read through the helper.
    unsafe {
        let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
        if TREE_MEMBERS.get(&tgid).is_none() {
            return 0;
        }
        if nn_tree_member_now() != MEMBER_LIFT {
            return 0;
        }
        let code = if file == 0 {
            CODE_ANONYMOUS
        } else {
            let file = file as *const u8;
            match read_ptr(file.add(off!(FILE_F_INODE_OFFSET))) {
                Some(inode) => match crate::role_maps::code_facts(file, inode) {
                    Some(f) => exec_verdict(&f, dir_mode(file)),
                    None => CODE_UNSAFE_DIR,
                },
                None => CODE_UNSAFE_DIR,
            }
        };
        if code == northnarrow_common::exec_marks::CODE_TRUSTED {
            return 0;
        }
        nn_tree_evict_current(reason, u64::from(code))
    }
}

/// Argument `i` of an LSM hook as a scalar (read through the helper: a
/// global function refuses the hook's typed pointer, "R1 is not a scalar",
/// on 5.15 to 7.0). Shared with the hooks that ask the tree's global
/// functions (`task_kill`, `sigio_guard`, `inode_protect`).
#[inline(always)]
pub(crate) unsafe fn raw_arg(ctx: &LsmContext, i: usize) -> u64 {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let args = aya_ebpf::EbpfContext::as_ptr(ctx) as *const u64;
        let mut v = 0u64;
        let _ = generated::bpf_probe_read_kernel(&mut v as *mut u64 as *mut c_void, 8, args.add(i) as *const c_void);
        v
    }
}

/// `bprm_check_security(struct linux_binprm *bprm)`: each pass of an exec
/// — a `#!` script's own file, its interpreter, a `binfmt_misc` handler —
/// judged for a member.
#[lsm(hook = "bprm_check_security")]
pub fn tree_bprm_check(ctx: LsmContext) -> i32 {
    unsafe { judge_bprm(&ctx) };
    0
}

/// `bprm_committed_creds(const struct linux_binprm *bprm)`: the final file,
/// past the exec's point of no return.
#[lsm(hook = "bprm_committed_creds")]
pub fn tree_bprm_commit(ctx: LsmContext) -> i32 {
    unsafe { judge_bprm(&ctx) };
    0
}

#[inline(always)]
unsafe fn judge_bprm(ctx: &LsmContext) {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
        if TREE_MEMBERS.get(&tgid).is_none() {
            return;
        }
        let bprm = raw_arg(ctx, 0) as *const u8;
        if bprm.is_null() {
            return;
        }
        let file = match read_ptr(bprm.add(off!(LINUX_BINPRM_FILE_OFFSET))) {
            Some(f) => f as u64,
            // no file to judge: fail closed (an anonymous verdict)
            None => 0,
        };
        let _ = nn_tree_judge_file(file, EVICT_EXEC);
    }
}

/// `sched_process_exec`: the new environment of a member's exec, laid out
/// in the new image by now, before its first instruction. A dangerous
/// variable, or an environment the bounded read cannot cover, evicts it.
#[btf_tracepoint(function = "sched_process_exec")]
pub fn tree_exec_env(_ctx: BtfTracePointContext) -> i32 {
    unsafe {
        let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
        if TREE_MEMBERS.get(&tgid).is_none() {
            return 0;
        }
        let _ = nn_tree_env();
    }
    0
}

/// [`tree_exec_env`]'s scan, a global function. Always 0.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn nn_tree_env() -> u64 {
    // SAFETY: the environment is read through the user-memory helpers into
    // this program's stack and scratch only.
    unsafe {
        if nn_tree_member_now() != MEMBER_LIFT {
            return 0;
        }
        let task = bpf_get_current_task() as *const u8;
        if env_clean(task) {
            return 0;
        }
        nn_tree_evict_current(EVICT_ENV, 0)
    }
}

/// Whether `task`'s environment (`mm->env_start` to `env_end`) is read
/// whole within the bounds and holds no dangerous variable.
#[inline(always)]
unsafe fn env_clean(task: *const u8) -> bool {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let (Some(os), Some(oe)) = (off_opt!(MM_STRUCT_ENV_START_OFFSET), off_opt!(MM_STRUCT_ENV_END_OFFSET)) else {
            return false;
        };
        let Some(mm) = read_ptr(task.add(off!(TASK_STRUCT_MM_OFFSET))) else {
            return false;
        };
        let (Some(start), Some(end)) = (read_u64(mm.add(os)), read_u64(mm.add(oe))) else {
            return false;
        };
        if end < start || end - start > ENV_MAX_BYTES {
            return false;
        }
        let Some(scratch) = TREE_ENV_SCRATCH.get_ptr_mut(0) else {
            return false;
        };
        let mut p = start;
        let mut vars = 0u32;
        while vars <= ENV_MAX_VARS {
            if p >= end {
                return true;
            }
            let mut head = [0u64; 3];
            let n = generated::bpf_probe_read_user_str(
                head.as_mut_ptr() as *mut c_void,
                ENV_HEAD as u32,
                p as *const c_void,
            );
            if n <= 0 {
                return false;
            }
            let len = if n as usize == ENV_HEAD {
                generated::bpf_probe_read_user_str(scratch as *mut c_void, ENV_VAR_MAX, p as *const c_void)
            } else {
                n
            };
            if len <= 0 || len as u32 >= ENV_VAR_MAX {
                return false;
            }
            if env_head_dangerous(&head) {
                return false;
            }
            p += len as u64;
            vars += 1;
        }
        false
    }
}

/// `mmap_file(struct file *file, unsigned long reqprot, unsigned long prot,
/// unsigned long flags)`: an executable mapping by a member.
#[lsm(hook = "mmap_file")]
pub fn tree_mmap_file(ctx: LsmContext) -> i32 {
    unsafe {
        let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
        if TREE_MEMBERS.get(&tgid).is_none() {
            return 0;
        }
        if (raw_arg(&ctx, 1) | raw_arg(&ctx, 2)) & PROT_EXEC != 0 {
            let _ = nn_tree_judge_file(raw_arg(&ctx, 0), EVICT_MAP);
        }
    }
    0
}

/// `shm_shmat(struct kern_ipc_perm *perm, char __user *shmaddr, int
/// shmflg)`: a System V segment attached executable (`SHM_EXEC`) by a
/// member — `do_shmat` maps it through `do_mmap`, past `mmap_file`, with
/// `VM_EXEC` from its birth (no `mprotect` follows): judged as anonymous
/// memory, as an executable mapping of no trusted file is (the review of
/// #647).
#[lsm(hook = "shm_shmat")]
pub fn tree_shmat(ctx: LsmContext) -> i32 {
    unsafe {
        let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
        if TREE_MEMBERS.get(&tgid).is_none() {
            return 0;
        }
        if raw_arg(&ctx, 2) & SHM_EXEC != 0 {
            let _ = nn_tree_judge_file(0, EVICT_MAP);
        }
    }
    0
}

/// `file_mprotect(struct vm_area_struct *vma, unsigned long reqprot,
/// unsigned long prot)`: an `mprotect` that makes a mapping executable,
/// judged on its file (a mapping already executable was judged at its
/// `mmap`).
#[lsm(hook = "file_mprotect")]
pub fn tree_mprotect(ctx: LsmContext) -> i32 {
    unsafe {
        let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
        if TREE_MEMBERS.get(&tgid).is_none() {
            return 0;
        }
        if (raw_arg(&ctx, 1) | raw_arg(&ctx, 2)) & PROT_EXEC == 0 {
            return 0;
        }
        let vma = raw_arg(&ctx, 0) as *const u8;
        if vma.is_null() {
            return 0;
        }
        let (Some(o_flags), Some(o_file)) =
            (off_opt!(VM_AREA_STRUCT_VM_FLAGS_OFFSET), off_opt!(VM_AREA_STRUCT_VM_FILE_OFFSET))
        else {
            // the vma cannot be told: judged as anonymous (fail closed)
            let _ = nn_tree_judge_file(0, EVICT_MAP);
            return 0;
        };
        if read_u64(vma.add(o_flags)).unwrap_or(0) & VM_EXEC != 0 {
            return 0;
        }
        let file = read_u64(vma.add(o_file)).unwrap_or(0);
        let _ = nn_tree_judge_file(file, EVICT_MAP);
    }
    0
}

// ── the members protected (D7) ──────────────────────────────────────────

/// `ptrace_access_check(struct task_struct *child, unsigned int mode)`: an
/// outsider's access to a member, in either mode, refused while the window
/// is open. Signed as the agent's own processes' (an ATTACH-mode access at
/// each attempt, a READ-mode one once an hour per caller image, journald's
/// packaged identity quiet; NOAUDIT never).
#[lsm(hook = "ptrace_access_check")]
pub fn tree_ptrace(ctx: LsmContext) -> i32 {
    unsafe {
        let target = raw_arg(&ctx, 0);
        if opaque(nn_tree_target_guarded(target)) == 0 {
            return 0;
        }
        let mode = raw_arg(&ctx, 1) as u32;
        let ttgid = read_u32((target as *const u8).add(off!(TASK_STRUCT_TGID_OFFSET))).unwrap_or(0);
        if mode & PTRACE_MODE_NOAUDIT == 0 {
            if mode & PTRACE_MODE_ATTACH != 0 {
                crate::inode_protect::emit_task_denial(FS_OP_PTRACE, u64::from(mode), ttgid);
            } else {
                crate::inode_protect::emit_task_read_denial(u64::from(mode), ttgid);
            }
        }
        -EPERM
    }
}

/// Lot 2.3a (D7, the review of #647): whether the write-open of `inode` (a
/// scalar pointer) is refused: a `cgroup.kill` or `cgroup.freeze` of the
/// window root's cgroup or of one above it ([`TREE_CGROUP_FILES`], of this
/// generation — the agent writes them when it arms the window), while the
/// window is open, by a caller outside the tree and outside the agent's
/// family: a member killed or frozen with its cgroup, which no `task_kill`
/// sees. Signed (`FS_OP_CGROUP_KILL`, `FS_OP_CGROUP_FREEZE`). 1 when
/// refused. A global function: an array read for any other open while no
/// tree grant is armed.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn nn_tree_cgroup_file(inode: u64) -> u64 {
    // SAFETY: the inode is read through the helper only; the maps are this
    // object's.
    unsafe {
        let Some(g) = grant_now() else {
            return 0;
        };
        if g.generation == 0 || inode == 0 {
            return 0;
        }
        let Some(key) = crate::inode_protect::read_inode_key(inode as *const c_void) else {
            return 0;
        };
        let Some(v) = TREE_CGROUP_FILES.get(&key) else {
            return 0;
        };
        let (generation, op) = (v[0], v[1]);
        if generation != g.generation || !tree_open(g, bpf_ktime_get_boot_ns(), session()) {
            return 0;
        }
        let caller = (bpf_get_current_pid_tgid() >> 32) as u32;
        if crate::task_kill::is_exempt_pid(caller) || member_now() == MEMBER_LIFT {
            return 0;
        }
        crate::inode_protect::emit_attempt(op as u8, key);
        1
    }
}

/// `file_receive(struct file *file)`: while the window is open, a
/// descriptor of an io_uring ring or of a protected inode received by a
/// process outside the agent's family is refused (the kernel does not say
/// who sent it: the boundary is closed both ways).
#[lsm(hook = "file_receive")]
pub fn tree_fd_receive(ctx: LsmContext) -> i32 {
    unsafe {
        let Some(g) = grant_now() else {
            return 0;
        };
        let s = session();
        if !tree_open(&g, bpf_ktime_get_boot_ns(), s) {
            return 0;
        }
        let caller = (bpf_get_current_pid_tgid() >> 32) as u32;
        if crate::task_kill::is_exempt_pid(caller) {
            return 0;
        }
        let file = raw_arg(&ctx, 0) as *const u8;
        if file.is_null() {
            return 0;
        }
        let key = match read_ptr(file.add(off!(FILE_F_INODE_OFFSET))) {
            Some(inode) => crate::inode_protect::read_inode_key(inode as *const c_void),
            None => None,
        };
        let protected = match key {
            Some(k) => crate::inode_protect::PROTECTED_INODES.get(&k).is_some(),
            None => false,
        };
        if !protected && !is_io_uring(file) {
            return 0;
        }
        crate::inode_protect::emit_attempt(FS_OP_FD_RECEIVE, key.unwrap_or(InodeKey { dev: 0, ino: 0 }));
        -EPERM
    }
}

/// `file` is an io_uring ring (its anonymous file's name).
#[inline(always)]
unsafe fn is_io_uring(file: *const u8) -> bool {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        let Some(dentry) = read_ptr(file.add(off!(FILE_F_PATH_OFFSET) + off!(PATH_DENTRY_OFFSET))) else {
            return false;
        };
        let Some(name) = read_ptr(dentry.add(off!(DENTRY_D_NAME_OFFSET) + off!(QSTR_NAME_OFFSET))) else {
            return false;
        };
        let mut w = [0u64; 2];
        if generated::bpf_probe_read_kernel_str(w.as_mut_ptr() as *mut c_void, 16, name as *const c_void) <= 0 {
            return false;
        }
        w[0] == IO_URING_LO && w[1] & IO_URING_HI_MASK == IO_URING_HI
    }
}
