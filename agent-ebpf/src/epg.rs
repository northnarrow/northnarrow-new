//! Exploit post-condition guard (lab PR 219, experimental).
//!
//! Whatever bug a local kernel exploit uses, it ends in a post-condition:
//! the task holds credentials it did not hold, or sits in namespaces or a
//! root it did not enter through the kernel's own mechanism. The guard
//! snapshots a task's credential, `nsproxy`, `fs` and root at `sys_enter`
//! and compares at `sys_exit`; `commit_creds`, `switch_task_namespaces` and
//! `set_fs_root` note that the mechanism ran, and for which call. The
//! decision is `northnarrow_common::epg` (the same code the agent's tests
//! run): a gain through no mechanism, or through a mechanism on behalf of a
//! call that never makes it, is an anomaly. Detect mode records it; enforce
//! mode also sends `SIGKILL` from the hook, so the signal is delivered
//! before the task returns to user mode with what it gained.
//!
//! Cost (design note, "Overhead"): a fully privileged task (host real uid 0,
//! every capability in effect) costs two reads at `sys_enter` and one map
//! miss at `sys_exit`. Any other task: one task-map lookup per hook, four
//! reads at entry and seven at exit, a comparison, no ring record. The
//! mechanism hooks run on rare paths only.
//!
//! The programs do nothing until the agent sets `EPG_CONFIG[ARMED]`, which
//! it does after the offsets are armed and their layout checked: the guard
//! never reads with a compiled-in offset.

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_task,
        bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel, gen,
    },
    macros::{fentry, map, raw_tracepoint},
    maps::{ring_buf::RingBufEntry, Array, HashMap, PerCpuArray, RingBuf},
    programs::{FEntryContext, RawTracePointContext},
    EbpfContext,
};
use northnarrow_common::epg::{
    self, abi, action, cfg, counter, kind, mech, point, ExitObservation, GuardConfig, Identity,
    NO_SYSCALL,
};
use northnarrow_common::ring_drops::ring_slot;
use northnarrow_common::wire::epg::{flags as evf, EpgEventRaw};

/// `EpgState.flags`.
const IN_SYSCALL: u32 = 1 << 0;
/// Re-take the whole snapshot at the next `sys_enter` (the task changed
/// through a mechanism outside a judged call: a fully privileged task's own
/// call, or task work).
const REBASE: u32 = 1 << 1;
/// An anomaly of this call was already reported (by a mechanism hook).
const REPORTED: u32 = 1 << 2;

/// `inum` positions.
const INUM_MNT: usize = 0;
const INUM_PID: usize = 1;
const INUM_NET: usize = 2;
const INUM_USER: usize = 3;

const SIGKILL: u32 = 9;

/// One tracked task (120 bytes), keyed by its `task_struct` address: stable
/// across `de_thread` (an exec by a non-leader thread changes its tid, not
/// its task), removed at `sched_process_exit` before the address can be
/// reused.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EpgState {
    id: Identity,
    cred: u64,
    nsproxy: u64,
    fs: u64,
    root: u64,
    root_epoch: u64,
    inum: [u32; 4],
    /// Raw number of the current (or last) call.
    nr: u32,
    flags: u32,
    /// `epg::mech` bits seen during the current call.
    mech: u32,
    /// Ring records this task produced ([`epg::REPORTS_PER_TASK`]).
    reports: u32,
}

/// Strict's tracked tasks. A plain hash map, not LRU: a flood of tasks
/// must not evict a task mid-call in silence. Sized by the agent at load
/// (`pid_max` unless configured) and not preallocated, so it holds every
/// live task and costs only the tracked ones; a full map leaves new tasks
/// untracked and counts them (`counter::UNTRACKED`). A non-preallocated map
/// in a raw tracepoint needs 6.1+: the agent checks the version and leaves
/// strict unavailable below it (attested).
#[map]
static EPG_TASKS: HashMap<u64, EpgState> =
    HashMap::with_max_entries(epg::TASKS_MAX, aya_ebpf::bindings::BPF_F_NO_PREALLOC);

/// The guard's configuration (`epg::GuardConfig`, one entry), written by
/// the agent: mode, capability mask and every offset, read once per run.
#[map]
pub static EPG_CONFIG: Array<GuardConfig> = Array::with_max_entries(1, 0);

/// `epg::counter` slots.
#[map]
pub static EPG_COUNTERS: PerCpuArray<u64> = PerCpuArray::with_max_entries(counter::SLOTS, 0);

/// Root epoch: bumped by every `set_fs_root` and `chroot_fs_refs` on the
/// host. A task whose root changed with no mechanism of its own is judged
/// only when no root changed anywhere since its previous call (a sibling's
/// `chroot` on a shared `fs_struct`, a `pivot_root` in its mount namespace).
#[map]
static EPG_ROOT_EPOCH: Array<u64> = Array::with_max_entries(1, 0);

/// Anomaly records (never on the fast path). Never pinned.
#[map]
pub static EPG_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

/// The configuration once armed, else `None` (the program does nothing).
#[inline(always)]
pub(crate) fn armed() -> Option<&'static GuardConfig> {
    match EPG_CONFIG.get(0) {
        Some(c) if c.armed == 1 => Some(c),
        _ => None,
    }
}

#[inline(always)]
pub(crate) fn count(slot: u32) {
    if let Some(c) = EPG_COUNTERS.get_ptr_mut(slot) {
        // SAFETY: per-CPU slot owned by this CPU for the program's run.
        unsafe { *c = (*c).wrapping_add(1) };
    }
}

#[inline(always)]
pub(crate) fn root_epoch() -> u64 {
    match EPG_ROOT_EPOCH.get(0) {
        Some(v) => *v,
        None => 0,
    }
}

#[inline(always)]
pub(crate) fn bump_root_epoch() {
    if let Some(e) = EPG_ROOT_EPOCH.get_ptr_mut(0) {
        // A lost increment under a race still changes the value, which is
        // all a reader compares.
        unsafe { *e = (*e).wrapping_add(1) };
    }
}

#[inline(always)]
pub(crate) unsafe fn rd<T>(addr: u64) -> Option<T> {
    bpf_probe_read_kernel::<T>(addr as *const T).ok()
}

/// `T` at `addr`, zeroes when unreadable: the helper clears its
/// destination on failure, so a read whose failure means 0 anyway takes no
/// branch on the helper's result. Every such branch was one more way
/// through the program for the 5.15 and 6.1 verifiers, which do not merge
/// them all again (lab PR 219: the exploit guard's programs near or past
/// the 1M-instruction limit; KERNEL_COMPATIBILITY "Older verifiers", rule
/// 10).
#[inline(always)]
pub(crate) unsafe fn peek<T>(addr: u64) -> T {
    let mut v = core::mem::MaybeUninit::<T>::uninit();
    let _ = gen::bpf_probe_read_kernel(
        v.as_mut_ptr() as *mut aya_ebpf::cty::c_void,
        core::mem::size_of::<T>() as u32,
        addr as *const aya_ebpf::cty::c_void,
    );
    // SAFETY: the helper writes every byte (the value, or zeroes).
    v.assume_init()
}

#[inline(always)]
pub(crate) fn o(v: u32) -> u64 {
    // Offsets are below 64 KiB (checked by the agent); the mask keeps the
    // sum a bounded scalar.
    (v & 0xffff) as u64
}

/// `task->cred`.
#[inline(always)]
pub(crate) unsafe fn task_cred(c: &GuardConfig, task: u64) -> Option<u64> {
    rd::<u64>(task + o(c.task_cred))
}

/// `[cap_permitted, cap_effective]`.
#[inline(always)]
pub(crate) unsafe fn cred_caps(c: &GuardConfig, cred: u64) -> Option<[u64; 2]> {
    rd::<[u64; 2]>(cred + o(c.cred_caps))
}

#[inline(always)]
pub(crate) unsafe fn cred_identity(c: &GuardConfig, cred: u64, caps: [u64; 2]) -> Option<Identity> {
    let ids = rd::<[u32; 8]>(cred + o(c.cred_uid))?;
    let user_ns = rd::<u64>(cred + o(c.cred_user_ns))?;
    Some(Identity {
        ids,
        cap_permitted: caps[0],
        cap_effective: caps[1],
        user_ns,
    })
}

#[inline(always)]
pub(crate) unsafe fn read_identity(c: &GuardConfig, cred: u64) -> Option<Identity> {
    let caps = cred_caps(c, cred)?;
    cred_identity(c, cred, caps)
}

/// `task->fs` and `task->fs->root.dentry` (0 when unreadable; a null `fs`
/// makes the second read fail, so its root is 0 too).
#[inline(always)]
pub(crate) unsafe fn fs_and_root(c: &GuardConfig, task: u64) -> (u64, u64) {
    let fs = peek::<u64>(task + o(c.task_fs));
    let root = peek::<u64>(fs + o(c.fs_root_dentry));
    (fs, root)
}

#[inline(always)]
pub(crate) unsafe fn nsproxy_of(c: &GuardConfig, task: u64) -> u64 {
    peek::<u64>(task + o(c.task_nsproxy))
}

/// `ns.inum` of the namespace whose pointer is at `ptr_addr` (0 when
/// unreadable: a null namespace makes the second read fail).
#[inline(always)]
unsafe fn inum_at(ptr_addr: u64, inum_off: u64) -> u32 {
    peek::<u32>(peek::<u64>(ptr_addr) + inum_off)
}

/// `ns.inum` of the mount, pid (for children) and network namespaces.
#[inline(always)]
pub(crate) unsafe fn ns_inums(c: &GuardConfig, nsproxy: u64) -> [u32; 3] {
    // A null `nsproxy` makes every read fail: zeroes.
    [
        inum_at(nsproxy + o(c.nsproxy_mnt), o(c.mnt_inum)),
        inum_at(nsproxy + o(c.nsproxy_pid), o(c.pid_inum)),
        inum_at(nsproxy + o(c.nsproxy_net), o(c.net_inum)),
    ]
}

#[inline(always)]
pub(crate) unsafe fn user_inum(c: &GuardConfig, user_ns: u64) -> u32 {
    peek::<u32>(user_ns + o(c.user_inum))
}

/// `TS_COMPAT` in `thread_info.status`: the current call is a 32-bit one
/// (not when unreadable).
#[inline(always)]
pub(crate) unsafe fn compat(c: &GuardConfig, task: u64) -> bool {
    peek::<u32>(task + o(c.task_ti_status)) & epg::TS_COMPAT != 0
}

/// The current task holds every capability with host real uid 0.
#[inline(always)]
unsafe fn current_fully_privileged(c: &GuardConfig, task: u64) -> bool {
    let ruid = bpf_get_current_uid_gid() as u32;
    if ruid != 0 {
        return false;
    }
    match task_cred(c, task).and_then(|cr| cred_caps(c, cr)) {
        Some(caps) => epg::fully_privileged(ruid, caps[1], c.full_cap_mask),
        None => false,
    }
}

/// The whole snapshot of `task` with credential `now`.
#[inline(always)]
unsafe fn baseline(c: &GuardConfig, s: *mut EpgState, task: u64, cred: u64, now: &Identity) {
    (*s).id = *now;
    (*s).cred = cred;
    let nsproxy = nsproxy_of(c, task);
    (*s).nsproxy = nsproxy;
    let (fs, root) = fs_and_root(c, task);
    (*s).fs = fs;
    (*s).root = root;
    (*s).root_epoch = root_epoch();
    let n = ns_inums(c, nsproxy);
    (*s).inum[INUM_MNT] = n[0];
    (*s).inum[INUM_PID] = n[1];
    (*s).inum[INUM_NET] = n[2];
    (*s).inum[INUM_USER] = user_inum(c, now.user_ns);
    (*s).mech = 0;
}

/// What one record carries.
pub(crate) struct Finding {
    pub kind: u8,
    pub abi: u8,
    pub nr: u32,
    pub before: Identity,
    pub after: Identity,
    /// `ns.inum` before: mount, pid (for children), network, user.
    pub before_ns: [u32; 4],
    pub after_user_inum: u32,
    pub after_ns: [u32; 3],
    pub flags: u8,
    /// `epg::point`.
    pub point: u8,
    /// `epg::mech` bits seen during the call (strict).
    pub mech: u32,
}

/// Count the anomaly and respond: in enforce, `SIGKILL` to the thread group
/// (pending, so delivered before the task's next return to user mode).
#[inline(always)]
pub(crate) unsafe fn respond(c: &GuardConfig) -> u8 {
    count(counter::ANOMALIES);
    if c.mode == cfg::MODE_ENFORCE {
        if gen::bpf_send_signal(SIGKILL) == 0 {
            count(counter::KILLS);
            action::KILLED
        } else {
            action::KILL_FAILED
        }
    } else {
        action::RECORDED
    }
}

/// Count, respond and, within the task's budget, put a record on the ring.
/// The response never depends on the ring.
#[inline(always)]
unsafe fn report(c: &GuardConfig, s: *mut EpgState, f: &Finding) {
    let act = respond(c);
    (*s).flags |= REPORTED;
    if (*s).reports >= epg::REPORTS_PER_TASK {
        count(counter::REPORTS_HELD);
        return;
    }
    (*s).reports += 1;
    emit(c, f, act);
}

/// A reserved, zeroed ring record with its header filled (time, task,
/// comm, kind, response, call, flags, point, variant); `None` when the
/// ring is full (counted).
#[inline(always)]
unsafe fn record(
    c: &GuardConfig,
    kind_: u8,
    act: u8,
    (abi_, nr_): (u8, u32),
    flags: u8,
    pt: u8,
) -> Option<RingBufEntry<EpgEventRaw>> {
    let mut entry = match EPG_EVENTS.reserve::<EpgEventRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(ring_slot::EXPLOIT_GUARD);
            return None;
        }
    };
    let r: *mut EpgEventRaw = entry.as_mut_ptr();
    crate::zero::zero(r);
    let pid_tgid = bpf_get_current_pid_tgid();
    (*r).timestamp_ns = bpf_ktime_get_ns();
    (*r).pid = (pid_tgid >> 32) as u32;
    (*r).tid = pid_tgid as u32;
    (*r).kind = kind_;
    (*r).action = act;
    (*r).abi = abi_;
    (*r).nr = nr_;
    (*r).flags = flags;
    (*r).point = pt;
    (*r).variant = c.variant as u8;
    crate::comm::comm_into(&mut (*r).comm);
    Some(entry)
}

/// One ring record (`EpgEventRaw`).
#[inline(always)]
pub(crate) unsafe fn emit(c: &GuardConfig, f: &Finding, act: u8) {
    let Some(mut entry) = record(c, f.kind, act, (f.abi, f.nr), f.flags, f.point) else {
        return;
    };
    let r: *mut EpgEventRaw = entry.as_mut_ptr();
    (*r).mechanisms = f.mech;
    (*r).before_ids = f.before.ids;
    (*r).after_ids = f.after.ids;
    (*r).before_cap_permitted = f.before.cap_permitted;
    (*r).before_cap_effective = f.before.cap_effective;
    (*r).after_cap_permitted = f.after.cap_permitted;
    (*r).after_cap_effective = f.after.cap_effective;
    (*r).before_user_ns = f.before_ns[3];
    (*r).after_user_ns = f.after_user_inum;
    (*r).before_mnt_ns = f.before_ns[0];
    (*r).before_pid_ns = f.before_ns[1];
    (*r).before_net_ns = f.before_ns[2];
    (*r).after_mnt_ns = f.after_ns[0];
    (*r).after_pid_ns = f.after_ns[1];
    (*r).after_net_ns = f.after_ns[2];
    entry.submit(0);
}

/// `ids` copied word by word into a ring record. An assignment between two
/// raw places (the task map into the ring) compiles to a call of the
/// `memmove` subprogram, which costs the precision marks rule 9 is about
/// (KERNEL_COMPATIBILITY "Older verifiers"); volatile stores keep the copy
/// inline.
#[inline(always)]
unsafe fn copy_ids(dst: *mut [u32; 8], src: *const [u32; 8]) {
    let d = dst as *mut u32;
    let s = src as *const u32;
    let mut i = 0;
    while i < 8 {
        core::ptr::write_volatile(d.add(i), *s.add(i));
        i += 1;
    }
}

/// A record of what a task holds, `before` = `after` (lite's degraded
/// evidence: a snapshot re-taken after a lost record). Written straight
/// into the ring, with no [`Finding`] on the stack: the mechanism hooks
/// that reach it are near the stack limit.
#[inline(always)]
pub(crate) unsafe fn emit_held(
    c: &GuardConfig,
    kind_: u8,
    act: u8,
    call: (u8, u32),
    flags: u8,
    pt: u8,
    id: &Identity,
    nsproxy: u64,
) {
    emit_change(c, kind_, act, call, flags, pt, id, nsproxy, id, nsproxy);
}

/// One ring record of a change: `before` and `before_nsproxy` what the
/// task held (lite: its record in the task map), `after` and
/// `after_nsproxy` what it holds now. Written straight into the ring with
/// no [`Finding`] on the stack: lite's `commit_creds` program reached the
/// 512-byte stack limit with one, and the copy cost the 5.15 and 6.1
/// verifiers paths and stack slots (lab PR 219).
#[inline(always)]
pub(crate) unsafe fn emit_change(
    c: &GuardConfig,
    kind_: u8,
    act: u8,
    call: (u8, u32),
    flags: u8,
    pt: u8,
    before: *const Identity,
    before_nsproxy: u64,
    after: &Identity,
    after_nsproxy: u64,
) {
    let Some(mut entry) = record(c, kind_, act, call, flags, pt) else {
        return;
    };
    let r: *mut EpgEventRaw = entry.as_mut_ptr();
    copy_ids(&mut (*r).before_ids, core::ptr::addr_of!((*before).ids));
    copy_ids(&mut (*r).after_ids, &after.ids);
    (*r).before_cap_permitted = (*before).cap_permitted;
    (*r).before_cap_effective = (*before).cap_effective;
    (*r).after_cap_permitted = after.cap_permitted;
    (*r).after_cap_effective = after.cap_effective;
    (*r).before_user_ns = user_inum(c, (*before).user_ns);
    (*r).after_user_ns = user_inum(c, after.user_ns);
    let b = ns_inums(c, before_nsproxy);
    (*r).before_mnt_ns = b[0];
    (*r).before_pid_ns = b[1];
    (*r).before_net_ns = b[2];
    let a = ns_inums(c, after_nsproxy);
    (*r).after_mnt_ns = a[0];
    (*r).after_pid_ns = a[1];
    (*r).after_net_ns = a[2];
    entry.submit(0);
}

/// A finding about credentials only (namespaces as in the snapshot).
#[inline(always)]
unsafe fn cred_finding(
    c: &GuardConfig,
    s: *mut EpgState,
    kind_: u8,
    abi_: u8,
    nr_: u32,
    after: &Identity,
    flags: u8,
    pt: u8,
) -> Finding {
    let after_user = if after.user_ns == (*s).id.user_ns {
        (*s).inum[INUM_USER]
    } else {
        user_inum(c, after.user_ns)
    };
    Finding {
        kind: kind_,
        abi: abi_,
        nr: nr_,
        before: (*s).id,
        after: *after,
        before_ns: (*s).inum,
        after_user_inum: after_user,
        after_ns: [(*s).inum[INUM_MNT], (*s).inum[INUM_PID], (*s).inum[INUM_NET]],
        flags,
        point: pt,
        mech: (*s).mech,
    }
}

/// The current comm is the lab's injection comm.
#[inline(always)]
pub(crate) unsafe fn injected_comm(c: &GuardConfig) -> bool {
    match crate::comm::current_comm() {
        Ok(comm) => epg::pack_comm(&comm) == (c.inject_comm_lo, c.inject_comm_hi),
        Err(_) => false,
    }
}

// ── sys_enter ───────────────────────────────────────────────────────────

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn epg_sys_enter(ctx: RawTracePointContext) -> i32 {
    if let Some(c) = armed() {
        unsafe { try_sys_enter(c, &ctx) };
    }
    0
}

#[inline(always)]
unsafe fn try_sys_enter(c: &GuardConfig, ctx: &RawTracePointContext) {
    // `sys_enter(struct pt_regs *regs, long id)`.
    let nr = *(ctx.as_ptr() as *const u64).add(1) as u32;
    let task = bpf_get_current_task();
    let Some(cred) = task_cred(c, task) else {
        return;
    };
    let Some(caps) = cred_caps(c, cred) else {
        return;
    };
    let ruid = bpf_get_current_uid_gid() as u32;
    if epg::fully_privileged(ruid, caps[1], c.full_cap_mask) {
        count(counter::SKIPPED_PRIVILEGED);
        return;
    }
    let Some(now) = cred_identity(c, cred, caps) else {
        return;
    };
    match EPG_TASKS.get_ptr_mut(&task) {
        Some(s) => {
            if (*s).flags & REBASE != 0 {
                baseline(c, s, task, cred, &now);
                count(counter::REBASED);
            } else {
                let bypassed = (*s).flags & IN_SYSCALL != 0;
                if bypassed {
                    count(counter::EXIT_BYPASSED);
                }
                if let Some(k) = epg::judge_enter(&(*s).id, &now) {
                    let (prev_abi, prev_nr) = if bypassed {
                        epg::split_abi((*s).nr, false)
                    } else {
                        (abi::NONE, NO_SYSCALL)
                    };
                    let mut fl = if bypassed { evf::EXIT_BYPASSED } else { 0 };
                    if cred != (*s).cred {
                        fl |= evf::CRED_REPLACED;
                    }
                    let f = cred_finding(c, s, k, prev_abi, prev_nr, &now, fl, point::SYS_ENTER);
                    report(c, s, &f);
                }
                if now.user_ns != (*s).id.user_ns {
                    (*s).inum[INUM_USER] = user_inum(c, now.user_ns);
                }
                (*s).id = now;
                (*s).cred = cred;
            }
            (*s).nr = nr;
            (*s).mech = 0;
            (*s).flags = ((*s).flags & !(REBASE | REPORTED)) | IN_SYSCALL;
        }
        None => {
            // Zeroed with volatile stores: `mem::zeroed()` compiles to the
            // `memset` subprogram (rule 9).
            let mut slot = core::mem::MaybeUninit::<EpgState>::uninit();
            crate::zero::zero(slot.as_mut_ptr());
            let fresh = &mut *slot.as_mut_ptr();
            baseline(c, fresh, task, cred, &now);
            fresh.nr = nr;
            fresh.flags = IN_SYSCALL;
            if EPG_TASKS.insert(&task, fresh, 0).is_ok() {
                count(counter::TRACKED);
            } else {
                count(counter::UNTRACKED);
            }
        }
    }
}

// ── sys_exit ────────────────────────────────────────────────────────────

#[raw_tracepoint(tracepoint = "sys_exit")]
pub fn epg_sys_exit(ctx: RawTracePointContext) -> i32 {
    if let Some(c) = armed() {
        unsafe { try_sys_exit(c, &ctx) };
    }
    0
}

#[inline(always)]
unsafe fn try_sys_exit(c: &GuardConfig, ctx: &RawTracePointContext) {
    let task = bpf_get_current_task();
    let Some(s) = EPG_TASKS.get_ptr_mut(&task) else {
        return;
    };
    if (*s).flags & IN_SYSCALL == 0 {
        // A fully privileged task's call (no snapshot taken), or a call the
        // kernel skipped before `sys_enter` (seccomp).
        return;
    }
    (*s).flags &= !IN_SYSCALL;
    count(counter::CHECKED);
    // `sys_exit(struct pt_regs *regs, long ret)`.
    let ret = *(ctx.as_ptr() as *const u64).add(1) as i64;
    let Some(cred) = task_cred(c, task) else {
        return;
    };
    let Some(after) = read_identity(c, cred) else {
        return;
    };
    let nsproxy = nsproxy_of(c, task);
    let (fs, root) = fs_and_root(c, task);
    let epoch = root_epoch();
    let gain = epg::cred_gain(&(*s).id, &after);
    let ns_changed = nsproxy != (*s).nsproxy;
    let fs_changed = fs != (*s).fs;
    let root_changed = root != (*s).root;
    let raw_nr = (*s).nr;
    let mut after_ns = [(*s).inum[INUM_MNT], (*s).inum[INUM_PID], (*s).inum[INUM_NET]];
    if ns_changed {
        after_ns = ns_inums(c, nsproxy);
    }
    let mut after_user = (*s).inum[INUM_USER];
    if after.user_ns != (*s).id.user_ns {
        after_user = user_inum(c, after.user_ns);
    }
    if gain != 0 || ns_changed || fs_changed || root_changed {
        // Slow path: something changed; read the ABI and judge.
        let (abi_, nr_) = epg::split_abi(raw_nr, compat(c, task));
        let obs = ExitObservation {
            before: (*s).id,
            after,
            mechanisms: (*s).mech,
            abi: abi_,
            nr: nr_,
            nsproxy_changed: ns_changed,
            fs_changed,
            root_changed,
            root_epoch_advanced: epoch != (*s).root_epoch,
        };
        if let Some(k) = epg::judge_exit(&obs) {
            if (*s).flags & REPORTED == 0 {
                let mut fl = 0u8;
                if cred != (*s).cred {
                    fl |= evf::CRED_REPLACED;
                }
                if ns_changed {
                    fl |= evf::NS_CHANGED;
                }
                if fs_changed {
                    fl |= evf::FS_CHANGED;
                }
                if root_changed {
                    fl |= evf::ROOT_CHANGED;
                }
                let f = Finding {
                    kind: k,
                    abi: abi_,
                    nr: nr_,
                    before: (*s).id,
                    after,
                    before_ns: (*s).inum,
                    after_user_inum: after_user,
                    after_ns,
                    flags: fl,
                    point: point::SYS_EXIT,
                    mech: (*s).mech,
                };
                report(c, s, &f);
            }
        }
        // Fallback for kernels where `chroot_fs_refs` cannot be hooked: a
        // successful `pivot_root` replaced the roots of the tasks of its
        // mount namespace.
        if epg::is_pivot_root(abi_, nr_) && ret == 0 {
            bump_root_epoch();
        }
    }
    // Lab fault injection: only when the agent (a `debug-trigger` build)
    // set a comm; a `getppid` exit of that process is reported, marked
    // injected, with nothing changed.
    if c.inject_comm_lo != 0
        && raw_nr == epg::nr::GETPPID
        && (*s).flags & REPORTED == 0
        && injected_comm(c)
    {
        let f = cred_finding(
            c,
            s,
            kind::CRED_NO_MECHANISM,
            abi::X64,
            raw_nr,
            &after,
            evf::INJECTED,
            point::SYS_EXIT,
        );
        report(c, s, &f);
    }
    (*s).id = after;
    (*s).cred = cred;
    (*s).nsproxy = nsproxy;
    (*s).fs = fs;
    (*s).root = root;
    (*s).root_epoch = root_epoch();
    (*s).inum[INUM_MNT] = after_ns[0];
    (*s).inum[INUM_PID] = after_ns[1];
    (*s).inum[INUM_NET] = after_ns[2];
    (*s).inum[INUM_USER] = after_user;
    (*s).mech = 0;
    (*s).flags &= !REPORTED;
}

// ── task exit ───────────────────────────────────────────────────────────

/// Forget the task before its `task_struct` can be freed and reused. Runs
/// armed or not: a disarmed guard must not leave entries behind.
#[raw_tracepoint(tracepoint = "sched_process_exit")]
pub fn epg_task_exit(_ctx: RawTracePointContext) -> i32 {
    let task = unsafe { bpf_get_current_task() };
    let _ = EPG_TASKS.remove(&task);
    0
}

// ── mechanisms ──────────────────────────────────────────────────────────

/// A mechanism outside any judged call: a fully privileged task's own
/// change is re-snapshotted at its next call; anyone else's is an anomaly,
/// then re-snapshotted too.
#[inline(always)]
unsafe fn outside_call(c: &GuardConfig, s: *mut EpgState, task: u64, anomaly: Option<Finding>) {
    if !current_fully_privileged(c, task) {
        if let Some(f) = anomaly {
            report(c, s, &f);
        }
    }
    (*s).flags |= REBASE;
}

/// `int commit_creds(struct cred *new)` — always for `current`.
#[fentry(function = "commit_creds")]
pub fn epg_commit_creds(ctx: FEntryContext) -> i32 {
    if let Some(c) = armed() {
        unsafe { try_commit_creds(c, &ctx) };
    }
    0
}

#[inline(always)]
unsafe fn try_commit_creds(c: &GuardConfig, ctx: &FEntryContext) {
    let task = bpf_get_current_task();
    let Some(s) = EPG_TASKS.get_ptr_mut(&task) else {
        return;
    };
    count(counter::COMMITS);
    let new = ctx.arg::<*const u8>(0) as u64;
    let Some(after) = read_identity(c, new) else {
        return;
    };
    if (*s).flags & IN_SYSCALL == 0 {
        // Compare with the credential being replaced, not the snapshot.
        let Some(old) = task_cred(c, task).and_then(|cr| read_identity(c, cr)) else {
            (*s).flags |= REBASE;
            return;
        };
        let gain = epg::cred_gain(&old, &after);
        let finding = match epg::judge_commit(gain, abi::NONE, NO_SYSCALL, false) {
            Some(k) => {
                let mut f = cred_finding(c, s, k, abi::NONE, NO_SYSCALL, &after, evf::CRED_REPLACED, point::COMMIT_CREDS);
                f.before = old;
                Some(f)
            }
            None => None,
        };
        outside_call(c, s, task, finding);
        return;
    }
    (*s).mech |= mech::COMMIT_CREDS;
    let gain = epg::cred_gain(&(*s).id, &after);
    if gain == 0 {
        return;
    }
    let (abi_, nr_) = epg::split_abi((*s).nr, compat(c, task));
    if let Some(k) = epg::judge_commit(gain, abi_, nr_, true) {
        let f = cred_finding(c, s, k, abi_, nr_, &after, evf::CRED_REPLACED, point::COMMIT_CREDS);
        report(c, s, &f);
    }
}

/// `void switch_task_namespaces(struct task_struct *p, struct nsproxy *new)`.
#[fentry(function = "switch_task_namespaces")]
pub fn epg_switch_ns(ctx: FEntryContext) -> i32 {
    if let Some(c) = armed() {
        unsafe { try_switch_ns(c, &ctx) };
    }
    0
}

#[inline(always)]
unsafe fn try_switch_ns(c: &GuardConfig, ctx: &FEntryContext) {
    let task = bpf_get_current_task();
    let p = ctx.arg::<*const u8>(0) as u64;
    let new = ctx.arg::<*const u8>(1) as u64;
    // `exit_task_namespaces` passes NULL; another task's switch is not
    // this task's mechanism.
    if p != task || new == 0 {
        return;
    }
    let Some(s) = EPG_TASKS.get_ptr_mut(&task) else {
        return;
    };
    let ns_after = ns_inums(c, new);
    let unchanged = (*s).id;
    if (*s).flags & IN_SYSCALL == 0 {
        let mut f = cred_finding(c, s, kind::NS_FROM_SYSCALL, abi::NONE, NO_SYSCALL, &unchanged, evf::NS_CHANGED, point::SWITCH_NS);
        f.after_ns = ns_after;
        outside_call(c, s, task, Some(f));
        return;
    }
    (*s).mech |= mech::SWITCH_NS;
    let (abi_, nr_) = epg::split_abi((*s).nr, compat(c, task));
    if let Some(k) = epg::judge_switch_ns(abi_, nr_, true) {
        let mut f = cred_finding(c, s, k, abi_, nr_, &unchanged, evf::NS_CHANGED, point::SWITCH_NS);
        f.after_ns = ns_after;
        report(c, s, &f);
    }
}

/// `void set_fs_root(struct fs_struct *fs, const struct path *path)`.
#[fentry(function = "set_fs_root")]
pub fn epg_set_fs_root(ctx: FEntryContext) -> i32 {
    if let Some(c) = armed() {
        unsafe { try_set_fs_root(c, &ctx) };
    }
    0
}

#[inline(always)]
unsafe fn try_set_fs_root(c: &GuardConfig, ctx: &FEntryContext) {
    // Every root change on the host advances the epoch, whoever makes it.
    bump_root_epoch();
    let task = bpf_get_current_task();
    let fs = ctx.arg::<*const u8>(0) as u64;
    let (my_fs, _) = fs_and_root(c, task);
    if fs == 0 || fs != my_fs {
        return;
    }
    let Some(s) = EPG_TASKS.get_ptr_mut(&task) else {
        return;
    };
    let unchanged = (*s).id;
    if (*s).flags & IN_SYSCALL == 0 {
        let f = cred_finding(c, s, kind::ROOT_FROM_SYSCALL, abi::NONE, NO_SYSCALL, &unchanged, evf::ROOT_CHANGED, point::SET_FS_ROOT);
        outside_call(c, s, task, Some(f));
        return;
    }
    (*s).mech |= mech::SET_FS_ROOT;
    let (abi_, nr_) = epg::split_abi((*s).nr, compat(c, task));
    if let Some(k) = epg::judge_set_fs_root(abi_, nr_, true) {
        let f = cred_finding(c, s, k, abi_, nr_, &unchanged, evf::ROOT_CHANGED, point::SET_FS_ROOT);
        report(c, s, &f);
    }
}

/// `void chroot_fs_refs(const struct path *old_root, const struct path
/// *new_root)` — `pivot_root` replacing the roots of the tasks rooted at
/// the old one. Optional (the `sys_exit` fallback covers a judged
/// `pivot_root`): only the epoch.
#[fentry(function = "chroot_fs_refs")]
pub fn epg_chroot_fs_refs(_ctx: FEntryContext) -> i32 {
    if armed().is_some() {
        bump_root_epoch();
    }
    0
}
