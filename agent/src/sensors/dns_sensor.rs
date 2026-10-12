//! Tappa 10.9 step 3 — userland half of the DNS sensor on the socket
//! buffer (`agent-ebpf/src/dns_skb.rs`, design
//! `docs/design/TAPPA10_9_SENSOR_ATTACH_POINTS_DESIGN.md` §12).
//!
//! The mode: [`want_skb`] (the `--dns-sensor` switch) before the
//! multiplexer starts, [`attach`] there, [`skb_active`] after. The record
//! is decoded in `common::model` (`From<&DnsQueryRaw>`), which walks the
//! wire bytes the kernel side copied.

use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use aya::Ebpf;
use common::btf_offsets::{slot, BTF_OFFSETS_ABSENT};
use tracing::{info, warn};

use crate::sensors::exe_identity::verifier_tail;

/// The socket-buffer programs in the eBPF object and their kernel functions.
pub const SKB4_PROGRAM: &str = "dns_udp_send_skb";
pub const SKB6_PROGRAM: &str = "dns_udp_v6_send_skb";
const SKB4_SYMBOL: &str = "udp_send_skb";
const SKB6_SYMBOL: &str = "udp_v6_send_skb";
/// The previous sensor: user memory at `udp_sendmsg` entry, IPv4 only.
pub const SENDMSG_PROGRAM: &str = "udp_sendmsg";

static SKB_WANTED: AtomicBool = AtomicBool::new(true);
static SKB_ACTIVE: AtomicBool = AtomicBool::new(false);
static SKB6_ACTIVE: AtomicBool = AtomicBool::new(false);

/// `--dns-sensor skb` (the default) or `sendmsg`; set before the
/// multiplexer starts.
pub fn want_skb(on: bool) {
    SKB_WANTED.store(on, Ordering::Relaxed);
}

/// Whether DNS queries are read from the socket buffer (IPv4 at least).
pub fn skb_active() -> bool {
    SKB_ACTIVE.load(Ordering::Relaxed)
}

/// Whether queries to IPv6 resolvers are observed at all.
pub fn ipv6_observed() -> bool {
    SKB6_ACTIVE.load(Ordering::Relaxed)
}

/// The offsets the socket-buffer programs cannot do without, resolved on
/// this kernel; the first one missing.
fn offsets_resolved() -> Option<&'static str> {
    let Some(r) = crate::anti_tamper::btf_revalidate::resolved() else {
        return Some("no kernel BTF");
    };
    for (s, name) in [
        (slot::SK_BUFF_HEAD_OFFSET, "sk_buff.head"),
        (slot::SK_BUFF_TAIL_OFFSET, "sk_buff.tail"),
        (
            slot::SK_BUFF_TRANSPORT_HEADER_OFFSET,
            "sk_buff.transport_header",
        ),
        (slot::SK_BUFF_DATA_LEN_OFFSET, "sk_buff.data_len"),
        (slot::FLOWI4_DADDR_OFFSET, "flowi4.daddr"),
        (slot::FLOWI4_ULI_OFFSET, "flowi4.uli"),
        (slot::FLOWI6_DADDR_OFFSET, "flowi6.daddr"),
        (slot::FLOWI6_ULI_OFFSET, "flowi6.uli"),
    ] {
        match r.values.iter().find(|(k, _)| *k == s) {
            Some((_, v)) if *v != BTF_OFFSETS_ABSENT => {}
            _ => return Some(name),
        }
    }
    None
}

/// Attach the DNS sensor: the socket-buffer kprobes when wanted and
/// attachable, else the `udp_sendmsg` kprobe. `attach_kprobe(ebpf,
/// program, symbol)` is the multiplexer's. Returns the IPv4 program that
/// runs.
///
/// Only the plain function names are attached: a compiler's renamed copy
/// (`.isra.0`, `.constprop.0`) may take different arguments. Without
/// `udp_send_skb` the agent falls back to `udp_sendmsg`; without only
/// `udp_v6_send_skb`, IPv4 stays on the socket buffer and IPv6 queries are
/// not observed (the `udp_sendmsg` program never saw them either).
pub fn attach(
    ebpf: &mut Ebpf,
    attach_kprobe: impl Fn(&mut Ebpf, &str, &str) -> Result<()>,
) -> Result<&'static str> {
    exempt_resolvers(ebpf);
    let sendmsg = |ebpf: &mut Ebpf| -> Result<&'static str> {
        attach_kprobe(ebpf, SENDMSG_PROGRAM, SENDMSG_PROGRAM)?;
        Ok(SENDMSG_PROGRAM)
    };
    if !SKB_WANTED.load(Ordering::Relaxed) {
        info!(
            "DNS sensor: sendmsg mode (--dns-sensor sendmsg) — udp_sendmsg, user memory, IPv4 only"
        );
        return sendmsg(ebpf);
    }
    if let Some(missing) = offsets_resolved() {
        warn!(
            missing,
            "DNS sensor: an offset the socket-buffer programs need is missing — attaching \
             udp_sendmsg (user memory, IPv4 only)"
        );
        return sendmsg(ebpf);
    }
    if let Err(e) = attach_kprobe(ebpf, SKB4_PROGRAM, SKB4_SYMBOL) {
        warn!(
            error = %verifier_tail(&e),
            "DNS sensor: {SKB4_SYMBOL} could not be attached — attaching udp_sendmsg (user \
             memory, IPv4 only)"
        );
        return sendmsg(ebpf);
    }
    SKB_ACTIVE.store(true, Ordering::Relaxed);
    match attach_kprobe(ebpf, SKB6_PROGRAM, SKB6_SYMBOL) {
        Ok(()) => {
            SKB6_ACTIVE.store(true, Ordering::Relaxed);
            info!(
                "DNS sensor armed on {SKB4_SYMBOL} + {SKB6_SYMBOL}: the kernel's copy of the \
                 query, IPv4 and IPv6 (Tappa 10.9 step 3)"
            );
        }
        Err(e) => warn!(
            error = %verifier_tail(&e),
            "DNS sensor armed on {SKB4_SYMBOL} only: {SKB6_SYMBOL} could not be attached — DNS \
             queries to IPv6 resolvers are NOT observed"
        ),
    }
    Ok(SKB4_PROGRAM)
}

/// Review 78: users of the local resolvers, whose forwarded queries the
/// kernel's DNS budgets (`agent-ebpf/src/dns_query.rs`) do not pace.
/// Dedicated service users only: a generic one (`nobody`) would exempt
/// anything that runs as it, and root is never exempt.
pub const RESOLVER_USERS: &[&str] = &[
    "systemd-resolve",
    "systemd-resolved",
    "unbound",
    "bind",
    "named",
    "dnsmasq",
    "pdns",
    "pdns-recursor",
    "knot-resolver",
];

/// The uids of [`RESOLVER_USERS`] in a `/etc/passwd` body.
fn resolver_uids(passwd: &str) -> Vec<u32> {
    passwd
        .lines()
        .filter_map(|line| {
            let mut f = line.split(':');
            let name = f.next()?;
            let uid: u32 = f.nth(1)?.parse().ok()?;
            (uid != 0 && RESOLVER_USERS.contains(&name)).then_some(uid)
        })
        .collect()
}

/// Write the resolvers' uids into the kernel's `DNS_EXEMPT_UIDS`.
fn exempt_resolvers(ebpf: &mut Ebpf) {
    let uids = resolver_uids(&std::fs::read_to_string("/etc/passwd").unwrap_or_default());
    let Some(map) = ebpf.map_mut("DNS_EXEMPT_UIDS") else {
        warn!("DNS budget: no DNS_EXEMPT_UIDS map — local resolvers are paced too");
        return;
    };
    let mut exempt = match aya::maps::HashMap::<_, u32, u8>::try_from(map) {
        Ok(m) => m,
        Err(e) => {
            warn!(error = %e, "DNS budget: DNS_EXEMPT_UIDS unusable — local resolvers are paced too");
            return;
        }
    };
    for uid in &uids {
        if let Err(e) = exempt.insert(uid, 1, 0) {
            warn!(uid, error = %e, "DNS budget: could not exempt a resolver user");
        }
    }
    info!(uids = ?uids, "DNS budget: local resolver users exempt (review 78)");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_uids_takes_dedicated_users_only() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\n\
                      nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n\
                      systemd-resolve:x:991:991:systemd Resolver:/:/usr/sbin/nologin\n\
                      unbound:x:120:127::/var/lib/unbound:/usr/sbin/nologin\n\
                      named:x:0:0:bad:/:/bin/sh\n\
                      alice:x:1000:1000::/home/alice:/bin/bash\n";
        assert_eq!(resolver_uids(passwd), vec![991, 120]);
    }

    /// The program names are the eBPF object's (`agent-ebpf/src/dns_skb.rs`,
    /// `dns_query.rs`): a rename there must fail here, not at attach time.
    #[test]
    fn program_names_match_the_ebpf_object() {
        let src = include_str!("../../../agent-ebpf/src/dns_skb.rs");
        assert!(src.contains(&format!("pub fn {SKB4_PROGRAM}(")));
        assert!(src.contains(&format!("pub fn {SKB6_PROGRAM}(")));
        let old = include_str!("../../../agent-ebpf/src/dns_query.rs");
        assert!(old.contains(&format!("pub fn {SENDMSG_PROGRAM}(")));
    }
}
