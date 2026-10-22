//! Lab PR 229 — the DNS names a process asks systemd-resolved for through
//! its NSS module, for the DNS attribution of its connects.
//!
//! On a host whose `/etc/nsswitch.conf` puts `resolve` before `dns`
//! (Debian 13, Fedora, Arch), glibc's lookups go through
//! `libnss_resolve.so.2`, which asks systemd-resolved over varlink (a unix
//! socket): the asking process sends no datagram to port 53, and the query
//! the socket-buffer sensor sees is systemd-resolved's own upstream one.
//! Nothing named the connect that followed. [`dns_nss_resolve`] is a uprobe
//! on the module's lookup entry points (`_nss_resolve_gethostbyname4_r`,
//! `…3_r`, `…2_r`, `…_r`; the userland attaches it to each), whose first
//! argument is the name, in the asking process's own context. The record
//! goes to the DNS ring with [`dns_flags::NSS`]: `query_name` holds the name
//! as text, NUL-terminated, read from user memory; no server, no type. The
//! DNS budgets of the datagram sensors apply ([`crate::dns_query::dns_admit`]).
//!
//! Verifier rules of `docs/operator/KERNEL_COMPATIBILITY.md` ("Older
//! verifiers"): the entry is zeroed by [`crate::zero::zero`] (no implicit
//! memset), the helper taking the context is `#[inline(always)]`.
use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_user_str_bytes,
    },
    macros::uprobe,
    programs::ProbeContext,
};
use northnarrow_common::wire::{dns_flags, DnsQueryRaw, QNAME_WIRE_LEN};

use crate::dns_query::DNS_QUERY_EVENTS;

#[uprobe]
pub fn dns_nss_resolve(ctx: ProbeContext) -> u32 {
    unsafe { try_dns_nss_resolve(&ctx) };
    0
}

#[inline(always)]
unsafe fn try_dns_nss_resolve(ctx: &ProbeContext) {
    // `_nss_resolve_gethostbyname*_r(const char *name, …)`.
    let name: *const u8 = match ctx.arg(0) {
        Some(p) => p,
        None => return,
    };
    if name.is_null() {
        return;
    }
    let admitted = match crate::dns_query::dns_admit() {
        Some(a) => a,
        None => return,
    };
    let mut entry = match DNS_QUERY_EVENTS.reserve::<DnsQueryRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::DNS);
            return;
        }
    };
    let raw: *mut DnsQueryRaw = entry.as_mut_ptr();
    crate::zero::zero(raw);
    (*raw).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    (*raw).uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;
    (*raw).timestamp_ns = bpf_ktime_get_ns();
    if let Ok(comm) = bpf_get_current_comm() {
        (*raw).comm = comm;
    }
    (*raw).flags = dns_flags::NSS | admitted.flags;
    (*raw).held = admitted.held;
    let dst = core::slice::from_raw_parts_mut((*raw).query_name.as_mut_ptr(), QNAME_WIRE_LEN);
    if let Ok(s) = bpf_probe_read_user_str_bytes(name, dst) {
        (*raw).qname_len = s.len() as u16;
    }
    entry.submit(0);
}
