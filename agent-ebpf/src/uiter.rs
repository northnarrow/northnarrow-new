//! Lot 275: the user buffer a `struct msghdr`'s iterator names, for the
//! sensors that read a send's or a receive's bytes where the process keeps
//! them (the TLS ClientHello at `tcp_sendmsg`, the DNS response after
//! `udp_recvmsg` copied it).
//!
//! The same two iterator shapes as the DNS query sensor's
//! (`crate::dns_query`): `ITER_UBUF`, one user buffer (6.0+: `send()`,
//! `recv()`, a one-segment `sendmsg()`), and `ITER_IOVEC` with one segment
//! (≤ 6.3 for those calls). The buffer's start is read; an iterator of any
//! other kind or of several segments is a documented miss (`None`). After a
//! receive the iterator has advanced past what the kernel copied: a
//! `ITER_UBUF` keeps its base (the offset moves), and a one-segment
//! `ITER_IOVEC` keeps its segment until the segment is full — then the
//! kernel moves to the next one and the count of segments drops to 0, which
//! reads as no buffer here.

use aya_ebpf::helpers::bpf_probe_read_kernel;

use crate::btf_offsets::{
    IOVEC_IOV_BASE_OFFSET, IOV_ITER_ITER_TYPE_OFFSET, IOV_ITER_IOV_OFFSET, IOV_ITER_NR_SEGS_OFFSET,
    IOV_ITER_UBUF_BASE_OFFSET, MSGHDR_MSG_ITER_OFFSET,
};

/// `ITER_UBUF` on the build kernel (6.4+); the agent arms this kernel's.
const ITER_UBUF: u8 = 0;
/// `ITER_IOVEC` on the build kernel (0 on ≤ 6.3).
const ITER_IOVEC: u8 = 1;

/// The user address of the buffer `msg`'s iterator reads or fills.
#[inline(always)]
pub(crate) unsafe fn user_base(msg_ptr: *const u8) -> Option<*const u8> {
    if msg_ptr.is_null() {
        return None;
    }
    let iter_type_off = off_opt!(IOV_ITER_ITER_TYPE_OFFSET)?;
    let iter = msg_ptr.add(off!(MSGHDR_MSG_ITER_OFFSET));
    let iter_type: u8 = bpf_probe_read_kernel::<u8>(iter.add(iter_type_off) as *const u8).ok()?;
    let iter_ubuf = crate::btf_offsets::rt_opt(
        northnarrow_common::btf_offsets::ITER_UBUF_VALUE_SLOT,
        ITER_UBUF as usize,
    )
    .map(|v| v as u8);
    let iter_iovec = crate::btf_offsets::rt_opt(
        northnarrow_common::btf_offsets::ITER_IOVEC_VALUE_SLOT,
        ITER_IOVEC as usize,
    )
    .map(|v| v as u8);
    let base: *const u8 = if iter_ubuf == Some(iter_type) {
        let ubuf_off = off_opt!(IOV_ITER_UBUF_BASE_OFFSET)?;
        bpf_probe_read_kernel::<*const u8>(iter.add(ubuf_off) as *const *const u8).ok()?
    } else if iter_iovec == Some(iter_type) {
        let nr_segs_off = off_opt!(IOV_ITER_NR_SEGS_OFFSET)?;
        let iov_off = off_opt!(IOV_ITER_IOV_OFFSET)?;
        let nr_segs: usize = bpf_probe_read_kernel::<usize>(iter.add(nr_segs_off) as *const usize).ok()?;
        if nr_segs != 1 {
            return None;
        }
        let iov: *const u8 = bpf_probe_read_kernel::<*const u8>(iter.add(iov_off) as *const *const u8).ok()?;
        if iov.is_null() {
            return None;
        }
        bpf_probe_read_kernel::<*const u8>(iov.add(off!(IOVEC_IOV_BASE_OFFSET)) as *const *const u8)
            .ok()?
    } else {
        return None;
    };
    if base.is_null() {
        None
    } else {
        Some(base)
    }
}
