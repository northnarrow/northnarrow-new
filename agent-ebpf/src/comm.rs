//! The current task's `comm`, read with no BPF-to-BPF call.
//!
//! `aya_ebpf::helpers::bpf_get_current_comm` zero-initialises a 16-byte
//! stack array first, which compiles to a call of the `memset` subprogram.
//! Up to 6.3 the verifier cannot carry a precision mark across a
//! subprogram call: the first branch whose outcome it knows past that call
//! marks every scalar of every state precise, states stop merging, and a
//! program that 6.8 verifies in a few thousand instructions runs into the
//! 1M-instruction limit on 6.1 (lab PR 219's exploit guard,
//! KERNEL_COMPATIBILITY "Older verifiers", rule 9).
//!
//! The helper does not write the bytes after the name's NUL on every
//! kernel: 5.15 pads them (`strncpy`), 6.1 copies up to the NUL and leaves
//! the rest as it was (`strscpy`). So the destination is zeroed first —
//! a reserved ring record already is; [`current_comm`] zeroes its stack
//! buffer with volatile stores (no `memset`). Compared whole, an unzeroed
//! tail made lab PR 219's injected comm match nothing on 6.1.

use aya_ebpf::{cty::c_void, helpers::generated};

/// `TASK_COMM_LEN`.
pub const COMM_LEN: usize = 16;

/// The current task's `comm`, NUL-padded, or the helper's error.
#[inline(always)]
pub fn current_comm() -> Result<[u8; COMM_LEN], i64> {
    // Two words (8-byte aligned), zeroed one by one, then the name and its
    // NUL written over them by the helper.
    let mut comm = core::mem::MaybeUninit::<[u64; 2]>::uninit();
    let words = comm.as_mut_ptr() as *mut u64;
    // SAFETY: both words are written before the helper and before any read.
    let ret = unsafe {
        core::ptr::write_volatile(words, 0);
        core::ptr::write_volatile(words.add(1), 0);
        generated::bpf_get_current_comm(words as *mut c_void, COMM_LEN as u32)
    };
    if ret == 0 {
        // SAFETY: initialised above; `[u64; 2]` and `[u8; 16]` have one size.
        Ok(unsafe { core::mem::transmute::<[u64; 2], [u8; COMM_LEN]>(comm.assume_init()) })
    } else {
        Err(ret)
    }
}

/// The current task's `comm` written straight into `dst`, a field of a
/// reserved ring-buffer record zeroed before: no stack copy, no copy loop,
/// no `memset`. On failure the helper leaves zeroes.
///
/// # Safety
/// `dst` points to 16 writable, zeroed bytes of ring-buffer or map memory
/// (the bytes after the name's NUL are not written on every kernel).
#[inline(always)]
pub unsafe fn comm_into(dst: *mut [u8; COMM_LEN]) {
    let _ = generated::bpf_get_current_comm(dst as *mut c_void, COMM_LEN as u32);
}
