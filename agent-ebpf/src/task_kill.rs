//! `task_kill` LSM hook — anti-tamper signal denial.
//!
//! Tappa 7 (ROADMAP.md): the agent must survive `SIGKILL`/`SIGTERM`
//! from any sender, including `root`. The kernel-mode policy is
//! enforced here by returning `-EPERM` when the target `tgid`
//! matches the userland-registered protected PID.
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
//! Tappa 8 dependency: the signed-channel exception is stubbed via
//! the [`KILL_OVERRIDE`] map. It is always empty in the Tappa 7
//! build, so root truly cannot kill the agent. Tappa 8 will wire an
//! Ed25519 verifier in userland that flips slot 0 to a non-zero
//! capability token after admin-signed approval.

use aya_ebpf::{
    cty::{c_int, c_void},
    helpers::bpf_probe_read_kernel,
    macros::{lsm, map},
    maps::Array,
    programs::LsmContext,
};

// ---------------------------------------------------------------------------
// Kernel struct offsets.
//
// `struct task_struct.tgid` byte offset, captured from
// `/sys/kernel/btf/vmlinux` on Ubuntu 24.04.4 / Linux 6.8.0-111-generic
// (2026-05-12): `bits_offset=19936` → 2492 bytes. The thread-group id
// is what userland calls "PID" — `getpid(2)` returns `tgid`, while the
// kernel's `task->pid` is the per-thread id. We compare against `tgid`.
//
// aya-ebpf 0.1 does not emit CO-RE field relocations from Rust struct
// definitions, so this constant is brittle across kernel rebuilds. The
// userland loader validates it at boot by re-reading the kernel BTF
// (Tappa 7 task 4 / `agent::anti_tamper`) before attaching the hook.
// ---------------------------------------------------------------------------
const TASK_STRUCT_TGID_OFFSET: usize = 2492;

const SIGKILL: c_int = 9;
const SIGTERM: c_int = 15;

/// Linux `EPERM` value; LSM hooks return `-errno` to deny.
const EPERM: c_int = 1;

/// Slot 0 holds the agent's `tgid`. `0` means "not registered yet",
/// which fails open during the brief window between agent startup
/// and userland populating the map.
#[map]
pub static PROTECTED_PID: Array<u32> = Array::with_max_entries(1, 0);

/// Tappa 8 stub: Ed25519-signed override capability. Slot 0 holds a
/// monotonic token; a non-zero value means "current admin-signed
/// kill request is in flight and may bypass the deny". In the
/// Tappa 7 ELF the map is shipped empty and never written by the
/// agent — that is the entire point of "anti-tamper Linux".
#[map]
pub static KILL_OVERRIDE: Array<u32> = Array::with_max_entries(1, 0);

#[lsm(hook = "task_kill")]
pub fn task_kill(ctx: LsmContext) -> i32 {
    unsafe { try_task_kill(&ctx) }
}

#[inline(always)]
unsafe fn try_task_kill(ctx: &LsmContext) -> i32 {
    // LSM-chain hygiene: if a prior hook on the chain already
    // produced a non-zero verdict, propagate it unchanged.
    let prev_retval: c_int = ctx.arg(4);
    if prev_retval != 0 {
        return prev_retval;
    }

    // We only police the two signals that can terminate a daemon
    // without coordination. Everything else (SIGCHLD, SIGWINCH,
    // SIGUSR1, …) goes through untouched so the agent's own
    // signal handlers (graceful reload, etc.) keep working.
    let sig: c_int = ctx.arg(2);
    if sig != SIGKILL && sig != SIGTERM {
        return 0;
    }

    let protected = match PROTECTED_PID.get(0) {
        Some(p) => *p,
        None => return 0,
    };
    if protected == 0 {
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
    let tgid_ptr = (target as *const u8).add(TASK_STRUCT_TGID_OFFSET) as *const u32;
    let target_tgid = match bpf_probe_read_kernel::<u32>(tgid_ptr) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    if target_tgid != protected {
        return 0;
    }

    // Tappa 8 escape hatch. The map is empty in the shipped Tappa 7
    // build; the lookup exists so the wiring is in place when the
    // Ed25519 verifier lands.
    let override_active = match KILL_OVERRIDE.get(0) {
        Some(v) => *v,
        None => 0,
    };
    if override_active != 0 {
        return 0;
    }

    -EPERM
}
