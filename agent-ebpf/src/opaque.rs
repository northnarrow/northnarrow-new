//! Lot 1.2: values the compiler must not reason about, so that a bound the
//! verifier needs is tested on the register the helper or the pointer
//! arithmetic then uses.
//!
//! LLVM moves a range test to wherever it is cheapest: onto the value the
//! tested one was computed from, onto a copy made before the test, or out
//! of the program when it proved the range earlier. The verifier tracks
//! registers, not values: a test on another register bounds nothing it
//! checks. With rustc 1.99's LLVM 22 (aya-ebpf 0.3) the 5.15 and 6.12
//! verifiers refused the exec programs three ways — the filename's read
//! size bounded on the whole `__data_loc` word (`R1 min value is outside
//! of the allowed memory range`), a path level's slot masks dropped
//! (`math between map_value pointer and register with unbounded min
//! value`), and an LSM verdict folded into `-(deny & 1) & -EACCES`
//! (`At program exit the register R0 ... should have been in [-4095, 0]`).
//! A volatile read of a local is what the agent already used for this
//! (`dns_answer`, `inode_protect`): the value reloaded from the stack is
//! one the compiler knows nothing about, and the test that follows is on
//! the register that holds it.

/// `v`, as a value the compiler knows nothing about: the test or the mask
/// that follows is kept, and made on the register this returns.
#[inline(always)]
pub(crate) fn opaque<T: Copy>(v: T) -> T {
    // SAFETY: a volatile read of a local of its own type, initialised
    // above: an aligned, valid read of 8 bytes at most from the stack.
    unsafe { core::ptr::read_volatile(&v) }
}

/// The kernel's `MAX_ERRNO`: an LSM program returns 0 or `-errno` with
/// `errno` at most this.
const MAX_ERRNO: i64 = 4095;

/// The refusal of the deny hook that returns through [`lsm_ret`],
/// `exec_check_lsm`: the exec policy's and the quarantine's `-EACCES`
/// (`execpol.rs`, `execq.rs`, each its own local constant, as here).
const EACCES: i32 = 13;

/// The verdict a deny hook's LSM program returns, in the range the
/// verifier allows at its exit, `[-MAX_ERRNO, 0]`, tested on the register
/// returned. The hook returns 0 or its refusal, `-EACCES`: those come out
/// as they went in. The other two branches are never reached by them; they
/// are there for the verifier, to which a verdict computed without
/// branches (`-(deny & 1) & -EACCES`) is any value, and they fail closed
/// (the review of #618): a positive value, which no deny hook returns, is
/// the hook's refusal, not an allow, and one below `-MAX_ERRNO` is
/// `-MAX_ERRNO`, a refusal still. Only 0 allows.
#[inline(always)]
pub(crate) fn lsm_ret(v: i32) -> i32 {
    let v = opaque(i64::from(v));
    if v > 0 {
        -EACCES
    } else if v < -MAX_ERRNO {
        -(MAX_ERRNO as i32)
    } else {
        v as i32
    }
}
