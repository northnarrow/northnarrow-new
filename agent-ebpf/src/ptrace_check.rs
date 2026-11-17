//! `ptrace_access_check` LSM hook — anti-tamper debugger denial.
//!
//! Tappa 7 (ROADMAP.md): the agent must be opaque to `ptrace(2)`
//! and to the `/proc/<pid>/{mem,maps,…}` family, including from
//! `root`. Both paths funnel through the kernel's
//! `security_ptrace_access_check` LSM call, so a single hook here
//! covers attach-style attacks (`PTRACE_ATTACH`, `PTRACE_SEIZE`)
//! and pure memory reads alike.
//!
//! Kernel hook signature (`linux/lsm_hook_defs.h`):
//! ```c
//! LSM_HOOK(int, 0, ptrace_access_check,
//!     struct task_struct *child,
//!     unsigned int mode)
//! ```
//! Aya appends the LSM chain `retval` as the last argument
//! (`arg(2)`), 0 if this is the first hook on the path. We honour
//! any prior denial by passing it through.
//!
//! Lot 367 (pre-alpha Phase 3-bis, F3b-1): the hook alone no longer
//! holds for the memory views on 6.16 and later. There `mm_access()`
//! (`kernel/fork.c`, `may_access_mm()`) lets a caller with `CAP_PERFMON`
//! or `CAP_SYS_ADMIN` through a READ-mode check the hook refused, so root
//! read the agent's `/proc/<pid>/environ`, `maps`, `smaps`, `pagemap` and
//! `auxv` on 7.0 while this hook said no. Their open is refused by
//! `file_open` (`cgroup_files::refuse_memory_view`), to the same callers
//! ([`target_is_protected`], [`caller_may_access`]); a READ-mode record
//! of this hook says only that the hook refused.
//!
//! Why deny `PTRACE_MODE_READ` and not just `PTRACE_MODE_ATTACH`:
//! a memory read of the agent process is sufficient to lift
//! in-memory secrets (Tappa 8 Ed25519 admin pubkey state, posture
//! machine, decision-engine internals). The Tappa 7 contract is
//! "the agent is not inspectable", so every mode is denied.
//!
//! Tappa 8 dependency: the signed-channel exception is stubbed via
//! the [`PTRACE_OVERRIDE`] map. It is always empty in the Tappa 7
//! build, so root truly cannot attach. Tappa 8 will wire the
//! Ed25519 verifier in userland that flips slot 0 to a non-zero
//! capability token after admin-signed approval (e.g. so an
//! incident-response engineer can run `gdb -p` after explicit
//! sign-off, without unloading the BPF program).

use aya_ebpf::{
    cty::{c_int, c_void},
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::{lsm, map},
    maps::{Array, HashMap},
    programs::LsmContext,
};

use crate::btf_offsets::TASK_STRUCT_TGID_OFFSET;
use northnarrow_common::wire::FS_OP_PTRACE;

/// BUG-011 (PHASE 15.1): trusted local-observer set. PIDs in this
/// map are permitted to `ptrace_access_check` PROTECTED_PIDS targets
/// — they can read `/proc/<protected_pid>/{exe,cmdline,status,…}` and
/// perform PTRACE_MODE_READ ops, but the `task_kill` hook is NOT
/// extended (an observer is not a controller; kill/term stays denied).
///
/// Populated by the agent userland after verifying that
/// `/proc/<candidate_pid>/exe` resolves to the installed watchdog
/// binary (kernel-resolved symlink, not forgeable from userspace).
/// See `agent/src/anti_tamper/mod.rs::register_protected_observer`
/// and the symmetric exe-verification helper at
/// `agent/src/posture/exempt.rs::resolve_verified_watchdog_pid`.
///
/// `max_entries = 8` is generous for V1 (watchdog only); future
/// trusted-observer integrations (nn-status pollers etc.) fit
/// without bumping the limit. Pinned by-name so the registration
/// survives agent restart and the kernel hook + userland share one
/// kernel object.
#[map]
pub static PROTECTED_OBSERVERS: HashMap<u32, u8> = HashMap::pinned(8, 0);

/// Linux `EPERM` value; LSM hooks return `-errno` to deny.
const EPERM: c_int = 1;

/// Tappa 8 stub: Ed25519-signed override capability for ptrace.
/// Slot 0 holds a monotonic token; a non-zero value means "current
/// admin-signed inspection request is in flight and may bypass the
/// deny". In the Tappa 7 ELF the map is shipped empty and never
/// written by the agent — root cannot attach a debugger, period.
///
/// Distinct from `task_kill::KILL_OVERRIDE` on purpose: signing off
/// "kill the agent" and signing off "let me read agent memory" are
/// independent capabilities and Tappa 8 should be able to grant
/// one without the other.
///
/// Pinned by-name alongside `PROTECTED_PIDS`, so slot 0 persists across
/// agent restarts. External audit EBPF-003: the agent zeroes it on boot,
/// and the hook honours it only when it carries this boot's session nonce
/// (`task_kill::AGENT_SESSION`), like `KILL_OVERRIDE` and
/// `FS_GRANT` — a value left in the map, by an earlier install
/// or through a map handle, is inert.
#[map]
pub static PTRACE_OVERRIDE: Array<u32> = Array::pinned(1, 0);

#[lsm(hook = "ptrace_access_check")]
pub fn ptrace_access_check(ctx: LsmContext) -> i32 {
    unsafe { try_ptrace_access_check(&ctx) }
}

#[inline(always)]
unsafe fn try_ptrace_access_check(ctx: &LsmContext) -> i32 {
    // No prev-retval read — see task_kill.rs comment for rationale.
    // Short version: kernel call_int_hook short-circuits on the first
    // non-zero LSM verdict, so we are only invoked when prev==0, and
    // aya 0.13's arg(N) read of the phony retval is unreliable on
    // Ubuntu 6.8's BPF-LSM trampoline.

    let target: *const c_void = ctx.arg(0);
    if target.is_null() {
        return 0;
    }

    // Read `child->tgid` via the probe helper. With LSM + BTF the
    // pointer is a kernel-trusted `PTR_TO_BTF_ID`, but we use the
    // explicit helper so the verifier accepts the read without a
    // CO-RE relocation we don't yet emit from Rust. Offset is
    // shared with `task_kill` and validated by userland at boot
    // against `/sys/kernel/btf/vmlinux`.
    let tgid_ptr = (target as *const u8).add(off!(TASK_STRUCT_TGID_OFFSET)) as *const u32;
    let target_tgid = match bpf_probe_read_kernel::<u32>(tgid_ptr) {
        Ok(v) => v,
        Err(_) => {
            // Lab PR 215: the target cannot be told; the access goes
            // through undecided, and is counted.
            crate::fail_open::bump(northnarrow_common::fail_open::hook::PTRACE_ACCESS_CHECK);
            return 0;
        }
    };

    // The protected processes ([`target_is_protected`]); lot 273c (the
    // review of #490): and PID 1, in attach mode only — a
    // debugger, `/proc/1/mem`, `process_vm_writev`. The deny hooks let PID 1
    // write back a unit's resource values and thaw a slice on the bytes
    // its `write(2)` carries; a PID 1 whose memory root could write would
    // swap them between the hook's read and the kernel's. Read-mode
    // access (`ps`, `/proc/1/environ`) is untouched, and a window lets a
    // debugger attach.
    let mode: u32 = ctx.arg(1);
    let init_attach = target_tgid == 1 && mode & PTRACE_MODE_ATTACH != 0;
    if !init_attach && !target_is_protected(target_tgid, target as *const u8) {
        return 0;
    }
    let caller_tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if caller_may_access(caller_tgid, init_attach) {
        return 0;
    }

    // Evidence: an ATTACH-mode access (debugger attach, /proc/<pid>/mem,
    // process_vm_readv/writev) at each attempt (the per-caller dedup); the
    // re-check of #567 (b): a READ-mode one (`nsenter` or `systemctl bind`
    // opening /proc/<pid>/ns/mnt, `lsof`, journald's /proc/<pid>/exe) once a
    // minute per caller and target. NOAUDIT asks LSMs explicitly not to
    // report (`ps` reading /proc/<pid>/stat): a silent denial.
    if mode & PTRACE_MODE_NOAUDIT == 0 {
        if mode & PTRACE_MODE_ATTACH != 0 {
            crate::inode_protect::emit_task_denial(FS_OP_PTRACE, mode as u64, target_tgid);
        } else {
            crate::inode_protect::emit_task_read_denial(mode as u64, target_tgid);
        }
    }
    -EPERM
}

/// Whether `target` (its tgid `target_tgid`) is one of the processes the
/// hook refuses access to: a protected pid, or a process running the
/// agent's or the watchdog's binary before it registered (external audit
/// EBPF-002). Lot 367: shared with the open of the agent's memory views
/// (`cgroup_files::refuse_memory_view`), which must refuse the same
/// processes the hook does.
#[inline(always)]
pub(crate) unsafe fn target_is_protected(target_tgid: u32, target: *const u8) -> bool {
    // Single bpf_map_lookup_elem against the shared PROTECTED_PIDS
    // hash map (see task_kill.rs for the rationale on the Tappa 7
    // task 6 single-PID → hash-set migration).
    // External audit EBPF-002: a process running the agent's or the
    // watchdog's binary is protected before it registers (its first moments
    // are when it may still take the agent's maps).
    // R14a: a worker is a protected target too (and runs the agent's binary).
    crate::task_kill::is_protected_pid(target_tgid) || crate::bpf_defense::task_runs_own_binary(target)
}

/// Whether the caller `caller_tgid` may access a protected process anyway
/// (`init_attach`: the target is PID 1, in attach mode). Lot 367: shared
/// with the open of the agent's memory views, so both let through the
/// same callers.
#[inline(always)]
pub(crate) fn caller_may_access(caller_tgid: u32, init_attach: bool) -> bool {
    // PHASE_D_002: caller-side mutual whitelist. If the CALLER's
    // tgid is itself in PROTECTED_PIDS, allow the ptrace_access —
    // this is the symmetric counterpart to W6's mutual PID
    // protection: agent and watchdog are both in PROTECTED_PIDS
    // and must therefore be able to read each other's /proc
    // interfaces (the watchdog reads /proc/<agent_pid>/exe to
    // reconstruct argv for respawn; the agent may in future read
    // /proc/<watchdog_pid>/status for stuck-detection symmetry).
    // Defends against unrelated root processes reading the agent's
    // memory while allowing the in-family supervisor relationship.
    //
    // `bpf_get_current_pid_tgid` returns `(tgid << 32) | pid`; we
    // want the tgid (upper 32 bits) to match the task_kill hook's
    // semantics (which checks target *tgid*, not pid).
    // R14a: an exempt caller only — a worker may not trace the agent, the
    // watchdog or another worker.
    if crate::task_kill::is_exempt_pid(caller_tgid) {
        return true;
    }
    if init_attach && crate::inode_protect::override_active() {
        return true;
    }

    // BUG-011 (PHASE 15.1): trusted-observer carve-out. The agent
    // userland registers the watchdog's verified PID here AFTER
    // confirming `/proc/<pid>/exe` matches the installed watchdog
    // binary (a kernel-resolved symlink that an attacker can't
    // substitute). Read-only access — task_kill is NOT extended,
    // so an observer cannot SIGKILL/SIGTERM us. Asymmetric trust:
    // PROTECTED_PIDS grants kill+observe immunity AND observer
    // rights; PROTECTED_OBSERVERS grants observer rights only.
    //
    // The map is agent-written; an attacker process cannot
    // self-register because the writer is the agent. An attacker
    // who execs at the watchdog's PID after the watchdog dies
    // would fail the agent's next refresh-cycle exe-check and be
    // evicted before the next ptrace attempt — minimal race
    // window (eviction latency, single agent timer cycle).
    // SAFETY: a lookup of this program's map.
    if unsafe { PROTECTED_OBSERVERS.get(&caller_tgid) }.is_some() {
        return true;
    }

    // Tappa 8 escape hatch. The map is empty in the shipped Tappa 7
    // build; the lookup exists so the wiring is in place when the
    // Ed25519 verifier lands. External audit EBPF-003: only a value equal
    // to this boot's session nonce opens it.
    let override_value = match PTRACE_OVERRIDE.get(0) {
        Some(v) => *v,
        None => 0,
    };
    let session = match crate::task_kill::AGENT_SESSION.get(0) {
        Some(v) => *v,
        None => 0,
    };
    override_value != 0 && override_value == session
}

/// `include/linux/ptrace.h`.
const PTRACE_MODE_ATTACH: u32 = 0x02;
const PTRACE_MODE_NOAUDIT: u32 = 0x04;
