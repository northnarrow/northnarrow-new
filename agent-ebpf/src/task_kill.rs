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
//! Tappa 8 dependency: the signed-channel exception is stubbed via
//! the [`KILL_OVERRIDE`] map. It is always empty in the Tappa 7
//! build, so root truly cannot kill the agent. Tappa 8 will wire an
//! Ed25519 verifier in userland that flips slot 0 to a non-zero
//! capability token after admin-signed approval.

use aya_ebpf::{
    cty::{c_int, c_void},
    helpers::bpf_probe_read_kernel,
    macros::{lsm, map},
    maps::{Array, HashMap},
    programs::LsmContext,
};

use crate::btf_offsets::TASK_STRUCT_TGID_OFFSET;

const SIGKILL: c_int = 9;
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

/// Tappa 8 stub: Ed25519-signed override capability. Slot 0 holds a
/// monotonic token; a non-zero value means "current admin-signed
/// kill request is in flight and may bypass the deny". In the
/// Tappa 7 ELF the map is shipped empty and never written by the
/// agent — that is the entire point of "anti-tamper Linux".
///
/// Pinned by-name alongside `PROTECTED_PIDS` so the pinned hook and
/// userland share one kernel object. Tappa-8 caveat: a pinned
/// override slot now PERSISTS across agent restart; Tappa 8 must
/// zero slot 0 on boot before trusting it (see commit message).
#[map]
pub static KILL_OVERRIDE: Array<u32> = Array::pinned(1, 0);

#[lsm(hook = "task_kill")]
pub fn task_kill(ctx: LsmContext) -> i32 {
    unsafe { try_task_kill(&ctx) }
}

#[inline(always)]
unsafe fn try_task_kill(ctx: &LsmContext) -> i32 {
    // No prev-retval read on this kernel. Aya 0.13 documents a
    // "phony retval at arg(N)" convention, but on Ubuntu 6.8's
    // BPF-LSM trampoline that slot is not reliably zero-initialised
    // — file_ioctl was silently early-returning because of garbage
    // at arg(3) (see 2026-05-12 diagnosis). The kernel's
    // call_int_hook macro short-circuits the LSM chain on the first
    // non-zero verdict anyway, so we are only ever invoked when all
    // prior LSMs returned 0; the prev-retval read is dead code.

    // We only police the two signals that can terminate a daemon
    // without coordination. Everything else (SIGCHLD, SIGWINCH,
    // SIGUSR1, …) goes through untouched so the agent's own
    // signal handlers (graceful reload, etc.) keep working.
    let sig: c_int = ctx.arg(2);
    if sig != SIGKILL && sig != SIGTERM {
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

    // Multi-PID lookup. `HashMap::get` in aya-ebpf returns a raw
    // pointer to the value; we only care about presence, so the
    // is_some() check collapses to a single bpf_map_lookup_elem
    // call. Marked unsafe because the returned reference can be
    // invalidated if the map mutates concurrently — we don't deref
    // it, so the invalidation window is irrelevant here.
    let is_protected = PROTECTED_PIDS.get(&target_tgid).is_some();
    if !is_protected {
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
