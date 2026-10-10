//! Inline zeroing of ring-buffer entries.
//!
//! `core::ptr::write_bytes` on an 800-byte entry lowers to a call to the
//! `memset` provided by compiler_builtins — a BPF-to-BPF *subprogram*
//! whose first argument is the ring-buffer pointer. Kernels before 6.x
//! only accept stack (`fp`) or scalar arguments for static subprograms
//! and reject the whole program ("R1 type=ctx expected=fp" on 5.15,
//! Ubuntu 22.04). Zeroing in place with volatile stores keeps the loop
//! inside the program (LLVM's loop-idiom pass would otherwise turn it
//! straight back into a memset call), so the object loads on every
//! supported kernel.

/// Zero `*p` (a `#[repr(C)]` event struct inside a ring-buffer entry,
/// 8-byte aligned by `RingBuf::reserve`). Bounded loops: the size is a
/// compile-time constant, so the verifier sees fixed trip counts.
#[inline(always)]
pub unsafe fn zero<T>(p: *mut T) {
    let bytes = core::mem::size_of::<T>();
    let words = bytes / 8;
    let p64 = p as *mut u64;
    let mut i = 0usize;
    while i < words {
        core::ptr::write_volatile(p64.add(i), 0u64);
        i += 1;
    }
    let p8 = p as *mut u8;
    let mut j = words * 8;
    while j < bytes {
        core::ptr::write_volatile(p8.add(j), 0u8);
        j += 1;
    }
}
