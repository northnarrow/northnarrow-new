//! `task_kill` LSM hook — anti-tamper signal denial.
//!
//! Tappa 7 (ROADMAP.md): the agent must survive `SIGKILL`/`SIGTERM`
//! from any sender, including `root`. The kernel-mode policy is
//! enforced here by returning `-EPERM` when the target `tgid` is
//! present in the [`PROTECTED_PIDS`] map. Task 6 (Tappa 7) widened
//! the map from a single-slot `Array<u32>` to a `HashMap<u32, u8>`
//! so the agent AND the watchdog can both be protected from one
//! lookup.
//!
//! Kernel hook signature (`linux/lsm_hook_defs.h`):
//! ```c
//! LSM_HOOK(int, 0, task_kill,
//!     struct task_struct *p,
//!     struct kernel_siginfo *info,
//!     int sig,
//!     const struct cred *cred)
//! ```
//! Aya appends the LSM chain `retval` as the last argument (`arg(4)`),
//! 0 if this is the first hook on the path. We honour any prior
//! denial by passing it through.
//!
//! PID 1 (systemd) is no exception by itself: it signals a protected
//! process only under a [`KILL_GRANT`] the agent writes for a signed
//! trusted-installer window, or as `systemd-shutdown` at the very end of
//! a shutdown (external audit EBPF-001).
//!
//! Lot 2.3a:
//! - a process that runs the agent's or the watchdog's binary is protected
//!   before it registers, as the ptrace and limits hooks protect it
//!   (a new instance in the spawn-to-registration span);
//! - while a tree window is open, its members are guarded from outsiders'
//!   signals, PID 1's included (but `systemd-shutdown`'s), signed
//!   (`crate::window_tree::nn_tree_target_guarded`, D7);
//! - every signal whose default action ends or stops a protected process is
//!   recorded: a refused one (`FS_OP_SIGNAL`), and one let through
//!   (`FS_OP_FATAL_SIGNAL`: PID 1 under the grant or as `systemd-shutdown`,
//!   the agent's family, the process itself) — lot 330 (a).
use northnarrow_common::window_tree::fatal_or_stop_by_default;
use northnarrow_common::wire::{InodeKey, KillGrant, FS_OP_FATAL_SIGNAL, FS_OP_SIGNAL};
use aya_ebpf::{
    cty::{c_int, c_void},
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{lsm, map},
    maps::{Array, HashMap, LruHashMap},
    programs::LsmContext,
};

use crate::btf_offsets::{
    TASK_STRUCT_GROUP_LEADER_OFFSET, TASK_STRUCT_REAL_PARENT_OFFSET, TASK_STRUCT_START_TIME_OFFSET, TASK_STRUCT_TGID_OFFSET,
};

/// Lot 2.3a (a new instance): `task` (thread group `tgid`; `raw` the same
/// pointer as a scalar, for the global functions) runs the agent's or the
/// watchdog's binary, is not that role's live holder, was started for its
/// role (a child of PID 1 in the role's unit cgroup, lot 374's
/// `nn_in_role_unit`), and has not registered within its first 60 s
/// (`northnarrow_common::window_tree::new_instance_protected`): a new
/// instance between its exec and its registration in `PROTECTED_PIDS`.
/// Its start is `start_time` (`CLOCK_MONOTONIC`, as `bpf_ktime_get_ns`);
/// unread, it is protected.
#[inline(always)]
fn new_instance(task: *const u8, raw: u64, tgid: u32) -> bool {
    // SAFETY: `task` is the hook's target task; every read below goes
    // through `bpf_probe_read_kernel`.
    unsafe {
        let role = match crate::bpf_defense::task_exe_key(task) {
            Some(k) => crate::bpf_defense::OWN_EXE_INODES.get(&k).copied().unwrap_or(0),
            None => 0,
        };
        if role == 0 {
            return false;
        }
        let holder = crate::bpf_defense::ROLE_TGIDS.get(u32::from(role - 1)).copied();
        let age = bpf_probe_read_kernel::<u64>(task.add(off!(TASK_STRUCT_START_TIME_OFFSET)) as *const u64)
            .ok()
            .map(|start| bpf_ktime_get_ns().saturating_sub(start));
        let parent_is_init = match bpf_probe_read_kernel::<*const u8>(
            task.add(off!(TASK_STRUCT_REAL_PARENT_OFFSET)) as *const *const u8,
        ) {
            Ok(p) if !p.is_null() => {
                bpf_probe_read_kernel::<u32>(p.add(off!(TASK_STRUCT_TGID_OFFSET)) as *const u32) == Ok(1)
            }
            _ => false,
        };
        let for_role = parent_is_init
            && crate::window_tree::opaque(crate::bpf_defense::nn_in_role_unit(raw, u64::from(role - 1))) == 1;
        northnarrow_common::window_tree::new_instance_protected(role, holder, tgid, for_role, age)
    }
}

/// Kept for the doc/trace vocabulary; the policy below is now
/// deny-by-default for every signal, not a KILL/TERM allowlist.
#[allow(dead_code)]
const SIGKILL: c_int = 9;
#[allow(dead_code)]
const SIGTERM: c_int = 15;

/// Linux `EPERM` value; LSM hooks return `-errno` to deny.
const EPERM: c_int = 1;

/// PIDs the userland loader has registered for protection. Multi-PID
/// support (Tappa 7 task 6) replaces the prior `PROTECTED_PID:
/// Array<u32>` (single slot) so the agent AND the watchdog can both
/// be protected from the same hook with one bpf_map_lookup_elem.
///
/// Value is unused — presence is the signal — kept as `u8` to keep
/// each map node tiny. `max_entries = 16` is generous headroom for
/// V1 (agent + watchdog + room for future nn-config-daemon, Tappa 9);
/// real-world occupancy is 2 entries.
///
/// `0` is NOT a valid PID, so an empty map fails open (no protection)
/// rather than denying every kill on the host.
///
/// `HashMap::pinned` (Tappa 7 task 6 commit #2) emits
/// `LIBBPF_PIN_BY_NAME`. Aya only consults `EbpfLoader::map_pin_path`
/// for maps carrying that flag (`aya-0.13.1` `bpf.rs:494`); a plain
/// `with_max_entries` declaration is created fresh on every load,
/// which split-brained the pinned LSM hook off a stale map. Pinned,
/// a restarted agent reuses the SAME kernel map object via
/// `bpf_get_object`, keeping the hook's map binding intact.
#[map]
pub static PROTECTED_PIDS: HashMap<u32, u8> = HashMap::pinned(16, 0);

/// R14a (plan §3.1): the roles of `tgid` — its `PROTECTED_PIDS` value
/// (`northnarrow_common::wire::pid_role`), 0 when it has no entry. Every
/// lookup of the map goes through [`is_protected_pid`] (a target) or
/// [`is_exempt_pid`] (a caller): a worker is protected, never exempt.
#[inline(always)]
pub fn pid_role(tgid: u32) -> u8 {
    // SAFETY: a lookup in this program's own map; the value is copied out
    // at once (no reference is kept across a map update).
    unsafe { PROTECTED_PIDS.get(&tgid).copied().unwrap_or(0) }
}

/// `tgid` is defended as a target (the agent, the watchdog, a worker).
#[inline(always)]
pub fn is_protected_pid(tgid: u32) -> bool {
    northnarrow_common::wire::pid_role::is_protected(pid_role(tgid))
}

/// `tgid` is trusted as a caller (the agent and the watchdog; never a
/// worker). Lot 2.2 (scaffold+): and it has not lost its role to an
/// unmarked executable mapping (`crate::role_maps`).
#[inline(always)]
pub fn is_exempt_pid(tgid: u32) -> bool {
    northnarrow_common::wire::pid_role::is_exempt(pid_role(tgid)) && crate::role_maps::nn_role_lost(u64::from(tgid)) == 0
}

/// External audit EBPF-001: when PID 1 may signal a protected process.
/// One slot, written by the agent only while a signed trusted-installer
/// window is open (the units are stopped or restarted with `systemctl`
/// during an upgrade or maintenance) and zeroed when it closes and at
/// every boot. It replaces BUG-010's `KILL_OVERRIDE`, which the agent
/// armed at boot for its whole life: any root shell could then stop or
/// kill the agent with `systemctl stop`/`kill`. See
/// [`KillGrant`](northnarrow_common::wire::KillGrant).
///
/// Pinned by name alongside `PROTECTED_PIDS` so the pinned hook and the
/// agent share one kernel object across restarts.
#[map]
pub static KILL_GRANT: Array<KillGrant> = Array::pinned(1, 0);

/// External audit EBPF-001: `(dev, ino)` of `systemd-shutdown`, the
/// program PID 1 becomes for the final stage of a shutdown (it signals
/// every remaining process, then halts or reboots). Written by the agent
/// at boot and kept current; zero means no carve-out.
#[map]
pub static SHUTDOWN_EXE: Array<InodeKey> = Array::pinned(1, 0);

/// BUG-010 (PHASE 15.1): per-boot session nonce. The agent picks a
/// fresh random u32 at boot and writes it here before LSM attach. Every
/// override and grant the hooks honour ([`KILL_GRANT`],
/// `FS_GRANT`, `PTRACE_OVERRIDE`) must carry it, so a value
/// pinned by an earlier run is dead after a restart.
#[map]
pub static AGENT_SESSION: Array<u32> = Array::pinned(1, 0);

/// Lab PR 225 (CM-18): the main processes of the host's other security
/// tools (auditd, rsyslogd, an EDR agent — the list `security-tools.v1`),
/// by tgid, written by the agent from `/proc` at boot and from their execs.
/// A stop or kill signal to one of them is reported, never refused
/// ([`observe_defender`]). Not pinned: the program is attached fresh every
/// boot and the agent fills the map after the load.
#[map]
pub static DEFENDER_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(256, 0);

/// Lab PR 225: the last report per (sender, target), to report a loop of
/// signals once a second.
#[map]
static DEFENDER_SEEN: LruHashMap<u64, u64> = LruHashMap::with_max_entries(1024, 0);

/// Signals that stop or end a process: SIGINT, SIGQUIT, SIGABRT, SIGKILL,
/// SIGTERM, SIGSTOP, SIGTSTP. Not SIGHUP and the user signals, which
/// logrotate and the tools' own clients send to reopen logs or reload.
#[inline(always)]
fn stops_or_ends(sig: c_int) -> bool {
    matches!(sig, 2 | 3 | 6 | 9 | 15 | 19 | 20)
}

/// Lab PR 225 (CM-18): `sig` to `target_tgid`, a registered security tool,
/// from anyone but PID 1 (systemd stopping a unit: NN-L-EVA-001 reads the
/// `systemctl` that asked), the tool itself, another registered tool or the
/// agent's family. One record on the file-open sensor's ring
/// (`open_reason::DEFENDER_SIGNAL`: `count` the signal, `flags` the target).
/// The signal is not refused: these tools are not the agent's to defend in
/// the kernel; a shell's builtin `kill`, which no exec shows, is seen here.
#[inline(always)]
unsafe fn observe_defender(target_tgid: u32, sig: c_int) {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        if !stops_or_ends(sig) || DEFENDER_PIDS.get(&target_tgid).is_none() {
            return;
        }
        let caller = (bpf_get_current_pid_tgid() >> 32) as u32;
        if caller == 1
            || caller == target_tgid
            || DEFENDER_PIDS.get(&caller).is_some()
            || is_exempt_pid(caller)
        {
            return;
        }
        let key = (u64::from(caller) << 32) | u64::from(target_tgid);
        let now = bpf_ktime_get_ns();
        if let Some(last) = DEFENDER_SEEN.get(&key) {
            if now.saturating_sub(*last) < 1_000_000_000 {
                return;
            }
        }
        let _ = DEFENDER_SEEN.insert(&key, &now, 0);
        let _ = crate::open_sensor::nn_open_emit(
            u64::from(northnarrow_common::wire::open_sensor::open_reason::DEFENDER_SIGNAL)
                | (u64::from(sig as u32) << 32),
            0,
            0,
            0,
            u64::from(target_tgid),
        );
    }
}

#[lsm(hook = "task_kill")]
pub fn task_kill(ctx: LsmContext) -> i32 {
    unsafe { try_task_kill(&ctx) }
}

#[inline(always)]
unsafe fn try_task_kill(ctx: &LsmContext) -> i32 {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        // No prev-retval read on this kernel. Aya 0.13 documents a
        // "phony retval at arg(N)" convention, but on Ubuntu 6.8's
        // BPF-LSM trampoline that slot is not reliably zero-initialised
        // — file_ioctl was silently early-returning because of garbage
        // at arg(3) (see 2026-05-12 diagnosis). The kernel's
        // call_int_hook macro short-circuits the LSM chain on the first
        // non-zero verdict anyway, so we are only ever invoked when all
        // prior LSMs returned 0; the prev-retval read is dead code.

        // Policy (audit `task-kill-signals-1`, 2026-10-08): towards a
        // PROTECTED target, DENY EVERY signal except an explicit allowlist.
        // The previous "only SIGKILL + SIGTERM" rule left the agent's own
        // shutdown handlers reachable by any root shell: SIGINT / SIGHUP
        // are graceful-stop signals in main.rs, SIGQUIT's default action
        // terminates, SIGSTOP freezes the process (ptrace is denied, stop
        // was not), SIGSEGV/SIGABRT/SIGBUS abort it. `kill -INT <agent>`
        // from root stopped the agent cleanly — the exact "even root can't
        // stop it" guarantee Tappa 7 promises. Note this hook only sees
        // USERSPACE-originated signals (kill/tkill/rt_sigqueueinfo):
        // kernel-generated SIGCHLD/SIGPIPE/faults never reach
        // security_task_kill, so no allowlist entry is needed for them.
        //
        // Allowed regardless of target:
        //   - sig 0: existence probe (the watchdog's `kill -0`, nn-admin).
        // Allowed by CALLER (checked after the protected-target lookup):
        //   - caller == target: the process signalling itself (raise,
        //     tgkill between its own threads).
        //   - caller is itself in PROTECTED_PIDS: the watchdog's
        //     stuck-recovery SIGINT→SIGKILL and the agent↔watchdog pair.
        //   - caller is PID 1 under a live grant, or PID 1 as
        //     systemd-shutdown (below).
        let sig: c_int = ctx.arg(2);
        if sig == 0 {
            return 0;
        }

        let target: *const c_void = ctx.arg(0);
        if target.is_null() {
            return 0;
        }

        // Read `target->tgid` via the probe helper. With LSM + BTF the
        // pointer is a kernel-trusted `PTR_TO_BTF_ID`, but we use the
        // explicit helper so the verifier accepts the read without a
        // CO-RE relocation we don't yet emit from Rust.
        let tgid_ptr = (target as *const u8).add(off!(TASK_STRUCT_TGID_OFFSET)) as *const u32;
        let target_tgid = match bpf_probe_read_kernel::<u32>(tgid_ptr) {
            Ok(v) => v,
            Err(_) => {
                // Lab PR 215: the target cannot be told; the signal goes
                // through undecided, and is counted.
                crate::fail_open::bump(northnarrow_common::fail_open::hook::TASK_KILL);
                return 0;
            }
        };

        // Multi-PID lookup. `HashMap::get` in aya-ebpf returns a raw
        // pointer to the value; we only care about presence, so the
        // is_some() check collapses to a single bpf_map_lookup_elem
        // call. Marked unsafe because the returned reference can be
        // invalidated if the map mutates concurrently — we don't deref
        // it, so the invalidation window is irrelevant here.
        // R14a: a worker is protected as a target, as the agent and the
        // watchdog are.
        // Lot 2.3a (a new instance): and a process running the agent's or the
        // watchdog's binary before it registered — not its role's holder, in
        // its first seconds ([`new_instance`]).
        let registered = is_protected_pid(target_tgid);
        let is_protected =
            registered || new_instance(target as *const u8, crate::window_tree::raw_arg(ctx, 0), target_tgid);
        let caller_tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
        if !is_protected {
            // Lot 2.3a (D7): a member of an open tree window, from outside
            // its tree (PID 1 included, but `systemd-shutdown`).
            // the target as a scalar (a global function refuses the hook's
            // typed pointer)
            if crate::window_tree::opaque(crate::window_tree::nn_tree_target_guarded(crate::window_tree::raw_arg(ctx, 0))) != 0
                && !(caller_tgid == 1 && pid1_is_final_shutdown())
            {
                crate::inode_protect::emit_signal(FS_OP_SIGNAL, sig as u32, target_tgid);
                return -EPERM;
            }
            // Lab PR 225: a stop or kill of another security tool, reported.
            // Lot 2.3b (scaffold+): a process the exec quarantine holds is
            // resumed by the agent's verdict only (a SIGCONT from anyone else
            // refused, signed)
            if execq_held_resume(target as *const u8, target_tgid, sig, caller_tgid) {
                crate::inode_protect::emit_signal(FS_OP_SIGNAL, sig as u32, target_tgid);
                return -EPERM;
            }
            observe_defender(target_tgid, sig);
            return 0;
        }

        // Self-signal, or an exempt process signalling a protected one (the
        // watchdog's stuck recovery, the agent's own supervision of the
        // watchdog and of its workers). An attacker's shell is in neither set;
        // R14a: a worker is protected, not exempt — it may not signal the
        // agent, the watchdog or another worker.
        if caller_tgid == target_tgid || is_exempt_pid(caller_tgid) {
            let_through(sig, target_tgid);
            return 0;
        }
        // Lot 2.3a: a process running our binary that holds no role
        // yet (`install.sh`'s `timeout 60 northnarrow-agent --own-dropins
        // check`) may be signalled by a process the window lifts for — a
        // member of the tree, or anyone under the host-wide grant — as a
        // registered one never is.
        if !registered && crate::inode_protect::override_active() {
            let_through(sig, target_tgid);
            return 0;
        }

        // External audit EBPF-001: PID 1 (systemd) signals a protected
        // process only (a) under a live grant — written for a signed
        // trusted-installer window, for the stop signals, until the window
        // ends, under this boot's session nonce — or (b) as
        // `systemd-shutdown`, the final stage of a shutdown, past which the
        // machine halts: the units are not stopped by the shutdown
        // transaction (no `Conflicts=shutdown.target`) and end here.
        // `systemctl stop`/`kill`/`restart` outside a window is refused like
        // a root shell's `kill`: systemd only relays root's request.
        if caller_tgid == 1 && (pid1_granted(sig) || pid1_is_final_shutdown()) {
            let_through(sig, target_tgid);
            return 0;
        }

        // Evidence: a refused signal is an attempt on the agent (rate-limited
        // by caller and signal: lot 2.3a).
        crate::inode_protect::emit_signal(FS_OP_SIGNAL, sig as u32, target_tgid);
        -EPERM
    }
}

/// Lot 2.3b (scaffold+; `northnarrow_common::wire::execq::execq_resume_refused`):
/// whether `sig` from `caller` to `target` (thread group `tgid`), a process
/// `EXECQ_STOPPED` names for its own start, would resume it before the
/// agent's verdict.
#[inline(always)]
unsafe fn execq_held_resume(target: *const u8, tgid: u32, sig: c_int, caller: u32) -> bool {
    // SAFETY: the body's 2021 unsafe context, made explicit (main.rs, "Unsafe code").
    unsafe {
        if sig != 18 {
            return false;
        }
        let held = crate::execq::EXECQ_STOPPED.get(&tgid);
        if held.is_none() {
            return false;
        }
        // the group leader's start (a SIGCONT to any thread resumes the group;
        // `de_thread` gave the exec'ing thread the leader's start)
        let leader = bpf_probe_read_kernel::<*const u8>(target.add(off!(TASK_STRUCT_GROUP_LEADER_OFFSET)) as *const *const u8)
            .unwrap_or(target);
        let start = bpf_probe_read_kernel::<u64>(leader.add(off!(TASK_STRUCT_START_TIME_OFFSET)) as *const u64).unwrap_or(0);
        northnarrow_common::wire::execq::execq_resume_refused(sig, held, start, is_exempt_pid(caller))
    }
}

/// Lot 2.3a (lot 330 a): a signal let through to a protected process is
/// recorded when its default action ends or stops it (minor: nothing was
/// refused).
#[inline(always)]
fn let_through(sig: c_int, target_tgid: u32) {
    if fatal_or_stop_by_default(sig) {
        crate::inode_protect::emit_signal(FS_OP_FATAL_SIGNAL, sig as u32, target_tgid);
    }
}

#[inline(always)]
fn pid1_granted(sig: c_int) -> bool {
    kill_grant_allows(sig)
}

/// The live [`KILL_GRANT`] of a signed trusted-installer window lets `sig`
/// through: one of its stop signals, before its deadline, under this
/// boot's session nonce. `task_kill` asks it for PID 1 only (lot 2.3a: the
/// signal through a file's owner no longer asks it, C112w).
#[inline(always)]
pub(crate) fn kill_grant_allows(sig: c_int) -> bool {
    let session = match AGENT_SESSION.get(0) {
        Some(v) => *v,
        None => return false,
    };
    match KILL_GRANT.get(0) {
        Some(g) => g.allows(sig, unsafe { bpf_ktime_get_ns() }, session),
        None => false,
    }
}

/// `comm` of `systemd-shutdown` (15 bytes and the NUL), as two words: an
/// array compare would lower to a `memcmp` call.
pub(crate) const SHUTDOWN_COMM_LO: u64 = u64::from_ne_bytes(*b"systemd-");
pub(crate) const SHUTDOWN_COMM_HI: u64 = u64::from_ne_bytes(*b"shutdow\0");

/// PID 1 is running `systemd-shutdown`: the comm (only PID 1 itself can
/// set it) AND the executable the agent recorded — a comm set through
/// `ptrace` of PID 1 is not enough.
#[inline(always)]
fn pid1_is_final_shutdown() -> bool {
    let comm = match bpf_get_current_comm() {
        Ok(c) => c,
        Err(_) => return false,
    };
    let words: [u64; 2] = unsafe { core::mem::transmute(comm) };
    if words[0] != SHUTDOWN_COMM_LO || words[1] != SHUTDOWN_COMM_HI {
        return false;
    }
    let want = match SHUTDOWN_EXE.get(0) {
        Some(k) if k.ino != 0 => *k,
        _ => return false,
    };
    match unsafe { crate::bpf_defense::caller_exe_key() } {
        Some(k) => k.dev == want.dev && k.ino == want.ino,
        None => false,
    }
}
