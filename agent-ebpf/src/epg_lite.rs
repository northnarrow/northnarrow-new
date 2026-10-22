//! Exploit post-condition guard, lite variant (lab PR 219; the default).
//!
//! No system-call hooks, so no cost on the system-call path. Two checks:
//!
//! - **At the mechanisms** (`commit_creds`, `switch_task_namespaces`,
//!   `set_fs_root`): the call in progress is read from the task's
//!   `pt_regs.orig_ax` (`bpf_task_pt_regs`) and judged with the same table
//!   as strict — `commit_creds` from `ioctl` is the ROP chain's signature.
//! - **At the uses of a privilege** (LSM `capable`, `bprm_check_security`,
//!   and `file_open` of a file owned by uid 0 that is not world-readable):
//!   the task's objective credential (`real_cred`: `override_creds` changes
//!   only `cred`) and its `nsproxy` are compared with the last ones the
//!   mechanisms gave it, kept in the task map (set at fork, at every
//!   commit and switch, or at the task's first use if it predates the
//!   guard). A gain no mechanism made — a `struct cred` written in place —
//!   is caught at its first use; in enforce the use is refused (`-EPERM`)
//!   and the task is sent `SIGKILL`, and every later use of a tainted task
//!   is refused too.
//!
//! The task map is an LRU hash (aya 0.13 cannot load task storage), keyed
//! by the `task_struct` address with the task's start time in the record
//! (`epg::lite_entry`): an address reused by a later task never inherits
//! a record, an exec by a non-leader thread keeps its own. Records are
//! deleted at `sched_process_exit`. A record the map evicted under
//! pressure is re-taken at the task's next hook, counted
//! (`BASELINES_LOST`, attested by the agent) and marked, and a re-taken
//! credential that holds privilege is put on the ring as degraded evidence
//! (`BASELINE_LOST`): eviction never makes an in-place write the new
//! baseline in silence.
//!
//! A task whose committed credential is fully privileged costs one read
//! (its start time) and one map lookup per use point, nothing else.

use aya_ebpf::{
    bindings::task_struct,
    helpers::{bpf_get_current_task, generated},
    macros::{btf_tracepoint, fentry, lsm, map},
    maps::LruHashMap,
    programs::{BtfTracePointContext, FEntryContext, LsmContext},
};
use northnarrow_common::epg::{
    self, abi, action, cfg, counter, kind, lite_flags as lf, point, GuardConfig, Identity,
    LiteEntry, LiteState, NO_SYSCALL,
};
use northnarrow_common::wire::epg::flags as evf;

use crate::epg::{
    armed, count, emit_change, emit_held, injected_comm, nsproxy_of, o, peek, rd, read_identity,
    respond,
};

const EPERM: i32 = 1;
const SIGKILL: u32 = 9;
/// `BPF_ANY`.
const ANY: u64 = 0;

/// Lite's per-task state, keyed by `task_struct` address (stable across
/// `de_thread`, unlike the tid). LRU: a fork always gets a record (an
/// eviction rather than a refusal), and an evicted one is detected at the
/// next hook ([`state_or_baseline`]). Sized by the agent at load
/// (`epg::LITE_TASKS_DEFAULT` at most unless configured; one entry when
/// lite does not run): an LRU map is preallocated.
#[map]
static EPG_LITE_TASKS: LruHashMap<u64, LiteState> =
    LruHashMap::with_max_entries(epg::LITE_TASKS_COMPILED, 0);

/// `task->start_time` (`CLOCK_MONOTONIC` ns at fork).
#[inline(always)]
unsafe fn start_time(c: &GuardConfig, task: u64) -> Option<u64> {
    rd::<u64>(task + o(c.task_start_time))
}

/// The record of the task at `task` that started at `start`, when it is
/// that task's ([`epg::lite_entry`]): one an earlier task left at the same
/// address is not; after an exec by a non-leader thread (whose start time
/// went back to its leader's) it is, and follows the new start time.
#[inline(always)]
unsafe fn lookup(task: u64, start: u64) -> Option<*mut LiteState> {
    let s = EPG_LITE_TASKS.get_ptr_mut(&task)?;
    match epg::lite_entry((*s).start_time, start) {
        LiteEntry::Current => Some(s),
        LiteEntry::ThreadExec => {
            (*s).start_time = start;
            Some(s)
        }
        LiteEntry::Stale => None,
    }
}

/// `task->real_cred` (an address for reads).
#[inline(always)]
unsafe fn real_cred(c: &GuardConfig, task: u64) -> Option<u64> {
    rd::<u64>(task + o(c.task_real_cred))
}

/// The call the current task (`task`) is in: `(abi, nr, in_syscall)`.
#[inline(always)]
unsafe fn current_call(c: &GuardConfig, task: u64) -> (u8, u32, bool) {
    let regs = generated::bpf_task_pt_regs(generated::bpf_get_current_task_btf()) as u64;
    if regs == 0 {
        return (abi::NONE, NO_SYSCALL, false);
    }
    let Some(orig_ax) = rd::<u64>(regs + epg::PT_REGS_ORIG_AX as u64) else {
        return (abi::NONE, NO_SYSCALL, false);
    };
    let compat = crate::epg::compat(c, task);
    match epg::syscall_of(orig_ax, compat) {
        Some((a, n)) => (a, n, true),
        None => (abi::NONE, NO_SYSCALL, false),
    }
}

/// Respond and record a finding against the task's committed state `s`:
/// the record's `before` is the state, its `after` `now` and `ns_now`.
/// Enforce taints the task (its later uses are refused); detect re-takes
/// the snapshot so one change is one record. The record goes straight into
/// the ring (`epg::emit_change`), before the state changes.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
unsafe fn report(
    c: &GuardConfig,
    s: *mut LiteState,
    kind_: u8,
    call: (u8, u32),
    now: &Identity,
    ns_now: u64,
    flags: u8,
    pt: u8,
) {
    let act = respond(c);
    if (*s).reports >= epg::REPORTS_PER_TASK {
        count(counter::REPORTS_HELD);
    } else {
        (*s).reports += 1;
        let flags = if (*s).flags & lf::REBASELINED != 0 {
            flags | evf::REBASELINED
        } else {
            flags
        };
        emit_change(
            c,
            kind_,
            act,
            call,
            flags,
            pt,
            core::ptr::addr_of!((*s).id),
            (*s).nsproxy,
            now,
            ns_now,
        );
    }
    if c.mode == cfg::MODE_ENFORCE {
        (*s).flags |= lf::TAINTED;
    } else {
        (*s).id = *now;
        (*s).nsproxy = ns_now;
    }
}

#[inline(always)]
fn fresh(id: Identity, cred: u64, nsproxy: u64, start_time: u64) -> LiteState {
    LiteState {
        id,
        cred,
        nsproxy,
        start_time,
        flags: lf::VALID,
        reports: 0,
    }
}

/// The current task's state (`found`, from [`lookup`]), with a snapshot of
/// what it holds now when it has none: first seen (it started before the
/// guard was armed, or no fork tracepoint sees it), or lost (it started
/// after, so its record was evicted: [`rebaselined`]). `true` with a new
/// snapshot (nothing to compare it with yet).
#[inline(always)]
unsafe fn state_or_baseline(
    c: &GuardConfig,
    found: Option<*mut LiteState>,
    task: u64,
    start: u64,
    now: &Identity,
    cred: u64,
    ns_now: u64,
    pt: u8,
) -> Option<(*mut LiteState, bool)> {
    if let Some(s) = found {
        if (*s).flags & lf::VALID != 0 {
            return Some((s, false));
        }
    }
    let task_flags = peek::<u32>(task + o(c.task_flags));
    let lost = epg::baseline_lost(start, task_flags, c.armed_at_ns);
    let mut init = fresh(*now, cred, ns_now, start);
    if lost {
        init.flags |= lf::REBASELINED;
    }
    if EPG_LITE_TASKS.insert(&task, &init, ANY).is_err() {
        return None;
    }
    let s = EPG_LITE_TASKS.get_ptr_mut(&task)?;
    if lost {
        count(counter::BASELINES_LOST);
        rebaselined(c, s, task, now, ns_now, pt);
    } else {
        count(counter::LAZY_BASELINES);
    }
    Some((s, true))
}

/// Degraded evidence: the record of a task started after arming was gone,
/// and its snapshot was just re-taken from what it holds now. A legitimate
/// change made while the record was missing and a credential written in
/// place look the same from here, so a re-taken credential that holds
/// privilege ([`epg::holds_privilege`]) goes on the ring, marked
/// `BASELINE_LOST` (before = after), within the task's budget. Recorded
/// only: never refused or killed (an eviction an unprivileged flood can
/// cause must not stop legitimate tasks). The count is the agent's to
/// attest.
#[inline(always)]
unsafe fn rebaselined(
    c: &GuardConfig,
    s: *mut LiteState,
    task: u64,
    now: &Identity,
    ns_now: u64,
    pt: u8,
) {
    if !epg::holds_privilege(now) {
        return;
    }
    if (*s).reports >= epg::REPORTS_PER_TASK {
        count(counter::REPORTS_HELD);
        return;
    }
    (*s).reports += 1;
    let (a, n, _) = current_call(c, task);
    emit_held(
        c,
        kind::CRED_NO_MECHANISM,
        action::RECORDED,
        (a, n),
        evf::BASELINE_LOST | evf::REBASELINED,
        pt,
        now,
        ns_now,
    );
}

/// A use of a privilege. 0 lets it proceed; `-EPERM` refuses it (enforce).
#[inline(always)]
unsafe fn use_point(c: &GuardConfig, pt: u8) -> i32 {
    let task = bpf_get_current_task();
    let Some(start) = start_time(c, task) else {
        return 0;
    };
    let found = lookup(task, start);
    use_point_found(c, pt, task, start, found)
}

/// [`use_point`] once the task's record was looked up (`found`).
#[inline(always)]
unsafe fn use_point_found(
    c: &GuardConfig,
    pt: u8,
    task: u64,
    start: u64,
    found: Option<*mut LiteState>,
) -> i32 {
    // Fast path: a fully privileged committed credential has nothing to gain.
    if let Some(s) = found {
        if (*s).flags & (lf::VALID | lf::TAINTED) == lf::VALID
            && c.inject_comm_lo == 0
            && epg::lite_skips(&(*s).id, c.full_cap_mask)
        {
            return 0;
        }
    }
    count(counter::USE_CHECKS);
    let Some(cred) = real_cred(c, task) else {
        return 0;
    };
    let Some(now) = read_identity(c, cred) else {
        return 0;
    };
    let ns_now = nsproxy_of(c, task);
    let Some((s, new)) = state_or_baseline(c, found, task, start, &now, cred, ns_now, pt) else {
        return 0;
    };
    if (*s).flags & lf::TAINTED != 0 && c.mode == cfg::MODE_ENFORCE {
        // Already found: every further use is refused.
        let _ = generated::bpf_send_signal(SIGKILL);
        count(counter::DENIED);
        return -EPERM;
    }
    let verdict = if c.inject_comm_lo != 0 && (*s).flags & lf::INJECTED == 0 && injected_comm(c) {
        (*s).flags |= lf::INJECTED;
        Some((kind::CRED_NO_MECHANISM, evf::INJECTED))
    } else if new {
        None
    } else {
        match epg::judge_use(&(*s).id, &now, (*s).nsproxy, ns_now) {
            Some(k) => {
                let mut fl = 0u8;
                if cred != (*s).cred {
                    fl |= evf::CRED_REPLACED;
                }
                if ns_now != (*s).nsproxy {
                    fl |= evf::NS_CHANGED;
                }
                Some((k, fl))
            }
            None => None,
        }
    };
    let Some((k, fl)) = verdict else {
        return 0;
    };
    let (a, n, _) = current_call(c, task);
    report(c, s, k, (a, n), &now, ns_now, fl, pt);
    if c.mode == cfg::MODE_ENFORCE {
        count(counter::DENIED);
        return -EPERM;
    }
    0
}

// ── use points ──────────────────────────────────────────────────────────

/// `int capable(const struct cred *cred, struct user_namespace *ns, int cap,
/// unsigned int opts)` — every capability check of the task.
#[lsm(hook = "capable")]
pub fn epg_lite_capable(_ctx: LsmContext) -> i32 {
    match armed() {
        Some(c) => unsafe { use_point(c, point::CAPABLE) },
        None => 0,
    }
}

/// `int bprm_check_security(struct linux_binprm *bprm)` — an exec, before
/// the new image's credential is committed.
#[lsm(hook = "bprm_check_security")]
pub fn epg_lite_exec(_ctx: LsmContext) -> i32 {
    match armed() {
        Some(c) => unsafe { use_point(c, point::EXEC) },
        None => 0,
    }
}

/// `int file_open(struct file *file)` — only for a file owned by uid 0 that
/// is not world-readable (two reads decide), or for a tainted task.
#[lsm(hook = "file_open")]
pub fn epg_lite_file_open(ctx: LsmContext) -> i32 {
    match armed() {
        Some(c) => unsafe { try_file_open(c, &ctx) },
        None => 0,
    }
}

/// One lookup of the task's record, shared with the use point: looked up
/// here and again in [`use_point`], every way through the first lookup
/// met every way through the second, which took this program past the
/// 1M-instruction limit of the 5.15 and 6.1 verifiers (lab PR 219;
/// KERNEL_COMPATIBILITY "Older verifiers", rule 10).
#[inline(always)]
unsafe fn try_file_open(c: &GuardConfig, ctx: &LsmContext) -> i32 {
    let task = bpf_get_current_task();
    let Some(start) = start_time(c, task) else {
        return 0;
    };
    let found = lookup(task, start);
    let mut tainted = false;
    if let Some(s) = found {
        let f = (*s).flags;
        if f & (lf::VALID | lf::TAINTED) == lf::VALID && epg::lite_skips(&(*s).id, c.full_cap_mask) {
            return 0;
        }
        tainted = f & lf::TAINTED != 0;
    }
    if !(tainted && c.mode == cfg::MODE_ENFORCE) {
        let file: u64 = ctx.arg::<u64>(0);
        let Some(inode) = rd::<u64>(file + o(c.file_inode)) else {
            return 0;
        };
        if inode == 0 {
            return 0;
        }
        let mode = rd::<u16>(inode + o(c.inode_mode)).unwrap_or(0o777);
        let owner = rd::<u32>(inode + o(c.inode_uid)).unwrap_or(u32::MAX);
        if !epg::file_open_is_guarded(owner, mode) {
            return 0;
        }
    }
    use_point_found(c, point::FILE_OPEN, task, start, found)
}

// ── baselines and mechanisms ────────────────────────────────────────────

/// `sched_process_exit(struct task_struct *p)`: forget the task before its
/// `task_struct` can be freed and reused, so the map holds live tasks only.
/// Runs armed or not: a disarmed guard must not leave records behind. A
/// record that outlives its task anyway (a hook after this one) is told
/// from the next task at the address by its start time.
#[btf_tracepoint(function = "sched_process_exit")]
pub fn epg_lite_task_exit(_ctx: BtfTracePointContext) -> i32 {
    let task = unsafe { bpf_get_current_task() };
    let _ = EPG_LITE_TASKS.remove(&task);
    0
}

/// `sched_process_fork(struct task_struct *parent, struct task_struct
/// *child)`: the child's first snapshot, before it runs (it replaces any
/// record a dead task left at the child's address).
#[btf_tracepoint(function = "sched_process_fork")]
pub fn epg_lite_fork(ctx: BtfTracePointContext) -> i32 {
    if let Some(c) = armed() {
        unsafe { try_fork(c, &ctx) };
    }
    0
}

#[inline(always)]
unsafe fn try_fork(c: &GuardConfig, ctx: &BtfTracePointContext) {
    let child = ctx.arg::<*const task_struct>(1) as u64;
    if child == 0 {
        return;
    }
    let Some(start) = start_time(c, child) else {
        return;
    };
    let Some(cred) = real_cred(c, child) else {
        return;
    };
    let Some(id) = read_identity(c, cred) else {
        return;
    };
    let init = fresh(id, cred, nsproxy_of(c, child), start);
    let _ = EPG_LITE_TASKS.insert(&child, &init, ANY);
}

/// `int commit_creds(struct cred *new)`: judge the call it runs for, check
/// that the credential it replaces is the one last committed (a write in
/// place laundered through a legitimate `setuid` is caught here), then
/// record the new one.
#[fentry(function = "commit_creds")]
pub fn epg_lite_commit_creds(ctx: FEntryContext) -> i32 {
    if let Some(c) = armed() {
        unsafe { try_commit_creds(c, &ctx) };
    }
    0
}

#[inline(always)]
unsafe fn try_commit_creds(c: &GuardConfig, ctx: &FEntryContext) {
    let task = bpf_get_current_task();
    let Some(start) = start_time(c, task) else {
        return;
    };
    let new = ctx.arg::<u64>(0);
    let Some(after) = read_identity(c, new) else {
        return;
    };
    let Some(old_cred) = real_cred(c, task) else {
        return;
    };
    let Some(old) = read_identity(c, old_cred) else {
        return;
    };
    let ns_now = nsproxy_of(c, task);
    let found = lookup(task, start);
    let Some((s, new_state)) = state_or_baseline(
        c,
        found,
        task,
        start,
        &old,
        old_cred,
        ns_now,
        point::COMMIT_CREDS,
    ) else {
        return;
    };
    count(counter::COMMITS);
    if !new_state && !epg::lite_skips(&(*s).id, c.full_cap_mask) {
        if let Some(k) = epg::judge_use(&(*s).id, &old, (*s).nsproxy, ns_now) {
            let (a, n, _) = current_call(c, task);
            report(c, s, k, (a, n), &old, ns_now, 0, point::COMMIT_CREDS);
        }
    }
    if !epg::fully_privileged(old.ids[epg::id::UID], old.cap_effective, c.full_cap_mask) {
        let gain = epg::cred_gain(&old, &after);
        if gain != 0 {
            let (a, n, in_sys) = current_call(c, task);
            if let Some(k) = epg::judge_commit(gain, a, n, in_sys) {
                // `before` is the credential being replaced.
                (*s).id = old;
                report(c, s, k, (a, n), &after, ns_now, evf::CRED_REPLACED, point::COMMIT_CREDS);
            }
        }
    }
    (*s).id = after;
    (*s).cred = new;
    (*s).flags |= lf::VALID;
}

/// `void switch_task_namespaces(struct task_struct *p, struct nsproxy *new)`.
#[fentry(function = "switch_task_namespaces")]
pub fn epg_lite_switch_ns(ctx: FEntryContext) -> i32 {
    if let Some(c) = armed() {
        unsafe { try_switch_ns(c, &ctx) };
    }
    0
}

#[inline(always)]
unsafe fn try_switch_ns(c: &GuardConfig, ctx: &FEntryContext) {
    let task = bpf_get_current_task();
    let p = ctx.arg::<u64>(0);
    let new = ctx.arg::<u64>(1);
    if p != task || new == 0 {
        return;
    }
    let Some(start) = start_time(c, task) else {
        return;
    };
    let Some(cred) = real_cred(c, task) else {
        return;
    };
    let Some(now) = read_identity(c, cred) else {
        return;
    };
    let ns_now = nsproxy_of(c, task);
    let found = lookup(task, start);
    let Some((s, _)) = state_or_baseline(
        c,
        found,
        task,
        start,
        &now,
        cred,
        ns_now,
        point::SWITCH_NS,
    ) else {
        return;
    };
    if !epg::lite_skips(&(*s).id, c.full_cap_mask) {
        let (a, n, in_sys) = current_call(c, task);
        if let Some(k) = epg::judge_switch_ns(a, n, in_sys) {
            report(c, s, k, (a, n), &now, new, evf::NS_CHANGED, point::SWITCH_NS);
        }
    }
    (*s).nsproxy = new;
}

/// `void set_fs_root(struct fs_struct *fs, const struct path *path)`.
#[fentry(function = "set_fs_root")]
pub fn epg_lite_set_fs_root(ctx: FEntryContext) -> i32 {
    if let Some(c) = armed() {
        unsafe { try_set_fs_root(c, &ctx) };
    }
    0
}

#[inline(always)]
unsafe fn try_set_fs_root(c: &GuardConfig, ctx: &FEntryContext) {
    let task = bpf_get_current_task();
    let fs = ctx.arg::<u64>(0);
    let my_fs = peek::<u64>(task + o(c.task_fs));
    if fs == 0 || fs != my_fs {
        return;
    }
    let Some(s) = start_time(c, task).and_then(|start| lookup(task, start)) else {
        return;
    };
    if (*s).flags & lf::VALID == 0 || epg::lite_skips(&(*s).id, c.full_cap_mask) {
        return;
    }
    let (a, n, in_sys) = current_call(c, task);
    if let Some(k) = epg::judge_set_fs_root(a, n, in_sys) {
        let now = (*s).id;
        let ns_now = (*s).nsproxy;
        report(c, s, k, (a, n), &now, ns_now, evf::ROOT_CHANGED, point::SET_FS_ROOT);
    }
}
