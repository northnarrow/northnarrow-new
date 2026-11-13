//! Tappa 10.9 step 3 — userland half of the DNS sensor on the socket
//! buffer (`agent-ebpf/src/dns_skb.rs`, design
//! `docs/design/TAPPA10_9_SENSOR_ATTACH_POINTS_DESIGN.md` §12).
//!
//! The mode: the `--dns-sensor` switch in the multiplexer's load plan,
//! [`attach`] there, which says what runs ([`DnsMode`]; R11c, lab PR 264:
//! they were process-wide switches, `want_skb` and `skb_active`). The record
//! becomes an event here ([`query_event`]; nn-model's `From<&DnsQueryRaw>`
//! until R09b, lab PR 254). R14b (plan §3.1): its name — bytes a process
//! wrote — is not read here: [`name_request`] hands them to the parse worker
//! as they are, and [`query_event`] takes the worker's decode, checked by
//! the core (`nn_proto::ipc::check_response`), or none: the event then
//! carries no name (`qname_partial`), and the core never walks the bytes
//! itself.

use anyhow::Result;
use aya::Ebpf;
use common::btf_offsets::{slot, BTF_OFFSETS_ABSENT};
use common::wire::{dns_flags, DnsQueryRaw};
use nn_model::Event;
use nn_proto::ipc::{QnameForm, QnameIn, QnameOut};
use tracing::{info, warn};

use crate::boot::manifest::{AttachPoints, Took};
use crate::sensors::contract::attach as A;
use crate::sensors::exe_identity::verifier_tail;

/// The socket-buffer programs in the eBPF object and their kernel functions.
pub const SKB4_PROGRAM: &str = "dns_udp_send_skb";
pub const SKB6_PROGRAM: &str = "dns_udp_v6_send_skb";
const SKB4_SYMBOL: &str = "udp_send_skb";
const SKB6_SYMBOL: &str = "udp_v6_send_skb";
/// The previous sensor: user memory at `udp_sendmsg` entry, IPv4 only.
pub const SENDMSG_PROGRAM: &str = "udp_sendmsg";

/// What [`attach`] armed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DnsMode {
    /// DNS queries are read from the socket buffer (IPv4 at least).
    pub skb: bool,
    /// Queries to IPv6 resolvers are observed (`udp_v6_send_skb`).
    pub ipv6: bool,
}

/// Lab PR 218: the degradation when `udp_v6_send_skb` does not attach.
pub const IPV6_NOT_OBSERVED: &str =
    "udp_v6_send_skb not attached: DNS queries to IPv6 resolvers are not observed";

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

/// Attach the DNS sensor: the socket-buffer kprobes when wanted
/// (`want_skb`: `--dns-sensor skb`, the default) and attachable, else the
/// `udp_sendmsg` kprobe, noted in `points`. `attach_kprobe(ebpf, program,
/// symbol)` is the multiplexer's. Returns what runs.
///
/// Only the plain function names are attached: a compiler's renamed copy
/// (`.isra.0`, `.constprop.0`) may take different arguments. Without
/// `udp_send_skb` the agent falls back to `udp_sendmsg`; without only
/// `udp_v6_send_skb`, IPv4 stays on the socket buffer and IPv6 queries are
/// not observed (the `udp_sendmsg` program never saw them either).
pub fn attach(
    ebpf: &mut Ebpf,
    want_skb: bool,
    points: &AttachPoints,
    attach_kprobe: impl Fn(&mut Ebpf, &str, &str) -> Result<()>,
) -> Result<DnsMode> {
    exempt_resolvers(ebpf);
    // The `udp_sendmsg` fallback's own signed record is the start's attest
    // phase's (external audit EBPF-006, `!skb`); the manifest names it.
    let sendmsg = |ebpf: &mut Ebpf| -> Result<DnsMode> {
        attach_kprobe(ebpf, SENDMSG_PROGRAM, SENDMSG_PROGRAM)?;
        points.note("dns", A::DNS_SENDMSG, Took::Fallback);
        Ok(DnsMode::default())
    };
    if !want_skb {
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
    let mut mode = DnsMode {
        skb: true,
        ipv6: false,
    };
    match attach_kprobe(ebpf, SKB6_PROGRAM, SKB6_SYMBOL) {
        Ok(()) => {
            mode.ipv6 = true;
            info!(
                "DNS sensor armed on {SKB4_SYMBOL} + {SKB6_SYMBOL}: the kernel's copy of the \
                 query, IPv4 and IPv6 (Tappa 10.9 step 3)"
            );
            points.note("dns", A::DNS_SKB, Took::Whole);
        }
        Err(e) => {
            warn!(
                error = %verifier_tail(&e),
                "DNS sensor armed on {SKB4_SYMBOL} only: {SKB6_SYMBOL} could not be attached — DNS \
                 queries to IPv6 resolvers are NOT observed"
            );
            points.note(
                "dns",
                A::DNS_SKB_V4,
                Took::Partial {
                    missing: vec![format!("{SKB6_SYMBOL}: {IPV6_NOT_OBSERVED}")],
                },
            );
            // Lab PR 218 (external audit App.D C-13): signed, not only a WARN.
            crate::boot::degradation::report("dns_sensor", IPV6_NOT_OBSERVED);
        }
    }
    Ok(mode)
}

/// Lab PR 229: the uprobe on systemd-resolved's NSS module
/// (`agent-ebpf/src/dns_nss.rs`).
pub const NSS_PROGRAM: &str = "dns_nss_resolve";
/// The module's name lookups. `_nss_resolve_gethostbyname2_r` and
/// `…_r` are systemd's fallbacks onto `…3_r` (`NSS_GETHOSTBYNAME_FALLBACKS`):
/// attached there too, each lookup would be recorded twice.
const NSS_SYMBOLS: &[&str] = &[
    "_nss_resolve_gethostbyname4_r",
    "_nss_resolve_gethostbyname3_r",
];
/// Where distributions install the module (Debian and Ubuntu multiarch,
/// the RPM and Arch layouts).
const NSS_LIBRARY_DIRS: &[&str] = &[
    "/usr/lib/x86_64-linux-gnu",
    "/lib/x86_64-linux-gnu",
    "/usr/lib/aarch64-linux-gnu",
    "/lib/aarch64-linux-gnu",
    "/usr/lib64",
    "/lib64",
    "/usr/lib",
];
const NSS_LIBRARY: &str = "libnss_resolve.so.2";

/// Lab PR 229: the copies of systemd-resolved's NSS module on this host —
/// each file once (a merged `/usr` names it twice), root's and not
/// writable by anyone else: a module another user could replace is not
/// one the system's lookups load.
fn nss_libraries() -> Vec<std::path::PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for dir in NSS_LIBRARY_DIRS {
        let Ok(path) = std::fs::canonicalize(std::path::Path::new(dir).join(NSS_LIBRARY)) else {
            continue;
        };
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            continue;
        }
        if seen.insert((meta.dev(), meta.ino())) {
            out.push(path);
        }
    }
    out
}

/// Lab PR 229: attach the uprobe on systemd-resolved's NSS module, so a
/// name resolved through it (`hosts: … resolve …` in nsswitch.conf: the
/// asking process sends no DNS datagram) attributes the connects that
/// follow. Optional: without the module, or when it does not attach, the
/// connects of those processes carry no name, as before (logged, and in
/// the boot manifest). A module replaced after the attach (an upgrade of
/// systemd) is a new file the probe is not on until the agent restarts.
pub fn attach_nss(ebpf: &mut Ebpf, points: &AttachPoints) {
    let libs = nss_libraries();
    if libs.is_empty() {
        info!("DNS sensor: no {NSS_LIBRARY} on this host — no NSS lookups to attribute");
        points.note("dns_nss", "none (no libnss_resolve)", Took::Absent);
        return;
    }
    let prog: &mut aya::programs::UProbe = match ebpf
        .program_mut(NSS_PROGRAM)
        .ok_or_else(|| anyhow::anyhow!("program {NSS_PROGRAM} missing from eBPF object"))
        .and_then(|p| {
            p.try_into()
                .map_err(|e| anyhow::anyhow!("{NSS_PROGRAM} is not a uprobe: {e}"))
        }) {
        Ok(p) => p,
        Err(e) => {
            warn!(error = %e, "DNS sensor: NSS lookups are not attributed");
            points.note("dns_nss", "not attached", Took::Absent);
            return;
        }
    };
    if let Err(e) = prog.load() {
        warn!(
            error = %verifier_tail(&anyhow::Error::from(e)),
            "DNS sensor: the NSS uprobe was refused — NSS lookups are not attributed"
        );
        points.note(
            "dns_nss",
            "not attached: the uprobe was refused",
            Took::Absent,
        );
        return;
    }
    let mut attached = Vec::new();
    for lib in &libs {
        for sym in NSS_SYMBOLS {
            match prog.attach(*sym, lib, aya::programs::uprobe::UProbeScope::AllProcesses) {
                Ok(_) => attached.push(format!("{}:{sym}", lib.display())),
                Err(e) => warn!(
                    library = %lib.display(),
                    symbol = sym,
                    error = %e,
                    "DNS sensor: NSS uprobe not attached here"
                ),
            }
        }
    }
    if attached.is_empty() {
        points.note("dns_nss", "not attached", Took::Absent);
        return;
    }
    info!(
        probes = %attached.join(", "),
        "DNS sensor: uprobe on systemd-resolved's NSS module — names resolved through it \
         attribute the connects that follow (lab PR 229)"
    );
    points.note(
        "dns_nss",
        &format!("uprobe:{}", attached.join("+")),
        Took::Whole,
    );
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

/// The uids of [`RESOLVER_USERS`] in the host's `/etc/passwd` (lot 275, the
/// second review of #495, R1: the DNS response pump's resolver identity).
pub fn host_resolver_uids() -> Vec<u32> {
    resolver_uids(&passwd())
}

/// Lot 311 (F4): `/etc/passwd` read as bytes — one account whose GECOS is
/// not UTF-8 (a Latin-1 full name) hid every resolver's uid.
fn passwd() -> String {
    passwd_at(std::path::Path::new("/etc/passwd"))
}

/// [`passwd`] at `path` (tests: a fixture).
fn passwd_at(path: &std::path::Path) -> String {
    crate::state_read::read_state(path).unwrap_or_default()
}

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
    let uids = resolver_uids(&passwd());
    {
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
    }
    // Lot 290 (item 3): written once per load — frozen
    if let Err(e) = crate::anti_tamper::bpf_defense::freeze_named(ebpf, "DNS_EXEMPT_UIDS") {
        warn!(error = %e, "DNS budget: DNS_EXEMPT_UIDS NOT frozen");
    }
    info!(uids = ?uids, "DNS budget: local resolver users exempt (review 78)");
}

// ── the record's event (R09b, lab PR 254: from nn-model; R14b: its name the
// parse worker's) ─────────────────────────────────────────────────────────────

/// R14b: what the parse worker is asked for this record's name — its bytes
/// as the kernel copied them (cut at the record's own buffer), and their
/// form: an NSS record's text ([`dns_flags::NSS`], lab PR 229), the
/// socket-buffer sensor's wire bytes that run past the name (its end and
/// the type after it asked for), or the `udp_sendmsg` sensor's name.
pub fn name_request(raw: &DnsQueryRaw) -> QnameIn {
    let len = (raw.qname_len as usize).min(raw.query_name.len());
    let form = if raw.flags & dns_flags::NSS != 0 {
        QnameForm::Nss
    } else if raw.flags & dns_flags::SKB != 0 {
        QnameForm::WireFindEnd
    } else {
        QnameForm::Wire
    };
    QnameIn {
        bytes: raw.query_name[..len].to_vec(),
        form,
    }
}

/// Lab PR 229: an NSS record's name, from the worker's decode of
/// [`name_request`]'s text (`None`: an empty name, or no decode).
pub fn nss_query_name(decoded: Option<&QnameOut>) -> Option<String> {
    decoded
        .filter(|d| !d.name.is_empty())
        .map(|d| d.name.clone())
}

/// The `Event::DnsQuery` of a DNS record (Wave 4 restructure, R09b, lab PR
/// 254: nn-model's `From<&DnsQueryRaw> for Event` until then; a `From`
/// between two other crates' types cannot be written in this one), with the
/// parse worker's decode of its name (R14b). The socket-buffer sensor's
/// type follows the name's end, which the worker found; the `udp_sendmsg`
/// sensor fills `qtype` in the kernel.
///
/// `decoded: None` — the worker did not answer (down, disabled, out of
/// time): the event carries no name (`""`) and is `qname_partial`, the
/// socket-buffer sensor's type unknown (0). The core does not decode the
/// bytes instead (plan §5).
pub fn query_event(raw: &DnsQueryRaw, decoded: Option<&QnameOut>) -> Event {
    let len = (raw.qname_len as usize).min(raw.query_name.len());
    let bytes = &raw.query_name[..len];
    let skb = raw.flags & dns_flags::SKB != 0;
    let (query_name, query_type, qname_partial) = match decoded {
        Some(d) if skb => match d.end.map(usize::from) {
            // the two bytes after the name's end, which the worker found
            // and the core bounded (`end` within the bytes)
            Some(end) => (
                d.name.clone(),
                bytes
                    .get(end..end + 2)
                    .map_or(0, |t| u16::from_be_bytes([t[0], t[1]])),
                false,
            ),
            None => (d.name.clone(), 0, true),
        },
        Some(d) => (d.name.clone(), raw.qtype, false),
        None => (String::new(), if skb { 0 } else { raw.qtype }, true),
    };
    Event::DnsQuery {
        pid: raw.pid,
        uid: raw.uid,
        comm: common::wire::cstr_lossy(&raw.comm).into_owned(),
        // FP-3: the sender exe is NOT carried on the wire (the BPF
        // event has no room for a path); userland resolves it
        // best-effort in `pump_dns_query` right after this decode.
        exe: None,
        query_name,
        query_type,
        dns_server: raw.dns_server,
        family: raw.family,
        timestamp_ns: raw.timestamp_ns,
        qname_partial,
        // lot 340: proven by the pump with the sender's image
        known_resolver: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The parse worker's decode of the record's name, as the worker gives
    /// it (`worker::serve::answer`, its code, run here in the test).
    fn decoded(raw: &DnsQueryRaw) -> QnameOut {
        use nn_proto::ipc::{Answer, Request};
        match crate::worker::serve::answer(&Request::DnsNames(vec![name_request(raw)])) {
            Answer::DnsNames(mut v) => v.remove(0),
            other => panic!("{other:?}"),
        }
    }

    /// The event with the worker's decode.
    fn event(raw: &DnsQueryRaw) -> Event {
        query_event(raw, Some(&decoded(raw)))
    }

    fn nss_of(raw: &DnsQueryRaw) -> Option<String> {
        nss_query_name(Some(&decoded(raw)))
    }
    use common::wire::{QNAME_LEN, QNAME_WIRE_LEN};

    #[test]
    fn dns_query_raw_to_event_decodes_qname() {
        let mut raw = DnsQueryRaw::zeroed();
        raw.pid = 99;
        raw.qtype = 1;
        let qname = b"\x07example\x03com\x00";
        raw.qname_len = qname.len() as u16;
        raw.query_name[..qname.len()].copy_from_slice(qname);
        match event(&raw) {
            Event::DnsQuery {
                query_name,
                query_type,
                ..
            } => {
                assert_eq!(query_name, "example.com");
                assert_eq!(query_type, 1);
            }
            _ => panic!("wrong variant"),
        }
        // Sanity: the size constant is honoured.
        assert_eq!(QNAME_LEN, 253);
    }

    /// Lab PR 229: the name of an NSS record — text as the process passed
    /// it — in the form a wire name decodes to.
    #[test]
    fn an_nss_record_names_the_text_the_process_passed() {
        let nss = |text: &[u8], len: usize| {
            let mut raw = DnsQueryRaw::zeroed();
            raw.flags = dns_flags::NSS;
            raw.query_name[..text.len()].copy_from_slice(text);
            raw.qname_len = len as u16;
            nss_of(&raw)
        };
        let name = b"foo.northnarrow-e2etest.invalid.";
        assert_eq!(
            nss(name, name.len()).as_deref(),
            Some("foo.northnarrow-e2etest.invalid"),
            "the root dot of an absolute name dropped, as on the wire"
        );
        assert_eq!(nss(b"example.com", 11).as_deref(), Some("example.com"));
        // up to the NUL, whatever the length says
        assert_eq!(nss(b"a.b\0junk", 8).as_deref(), Some("a.b"));
        // a byte outside printable ASCII, and the backslash, as \DDD
        assert_eq!(nss(b"x\ny\\z", 5).as_deref(), Some("x\\010y\\092z"));
        assert_eq!(nss(b"", 0), None);
        assert_eq!(nss(b".", 1), None);
        // a length past the buffer is cut to it
        let mut raw = DnsQueryRaw::zeroed();
        raw.flags = dns_flags::NSS;
        raw.query_name.fill(b'a');
        raw.qname_len = u16::MAX;
        assert_eq!(nss_of(&raw).map(|n| n.len()), Some(QNAME_WIRE_LEN));
    }

    /// A record from the socket-buffer sensor (Tappa 10.9 step 3): wire
    /// bytes from the start of the name; the type comes after the root label.
    fn skb_raw(wire: &[u8]) -> DnsQueryRaw {
        let mut raw = DnsQueryRaw::zeroed();
        raw.flags = dns_flags::SKB;
        raw.qtype = 0xffff; // ignored in this mode
        raw.qname_len = wire.len() as u16;
        raw.query_name[..wire.len()].copy_from_slice(wire);
        raw
    }

    fn dns_fields(ev: Event) -> (String, u16, bool) {
        match ev {
            Event::DnsQuery {
                query_name,
                query_type,
                qname_partial,
                ..
            } => (query_name, query_type, qname_partial),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn skb_record_takes_the_type_after_the_root_label() {
        // example.com, TXT (16), class IN
        let raw = skb_raw(b"\x07example\x03com\x00\x00\x10\x00\x01");
        assert_eq!(dns_fields(event(&raw)), ("example.com".into(), 16, false));
    }

    /// The `udp_sendmsg` sensor stopped at the first zero byte, so a zero
    /// inside a label cut the name; the label walk does not.
    #[test]
    fn skb_record_keeps_a_label_with_a_zero_byte() {
        let raw = skb_raw(b"\x05ab\x00cd\x04evil\x00\x00\x01\x00\x01");
        assert_eq!(
            dns_fields(event(&raw)),
            // External audit NN-AUD-185: `\000`, not a `?` shared by every
            // unprintable byte
            ("ab\\000cd.evil".into(), 1, false)
        );
    }

    /// The name runs past the bytes read (a corked send: the rest is in a
    /// page fragment): partial, no type.
    #[test]
    fn skb_record_without_a_root_label_is_partial() {
        let raw = skb_raw(b"\x10aaaaaaaaaaaaaaaa\x06bbb");
        let (name, qtype, partial) = dns_fields(event(&raw));
        assert_eq!(name, "aaaaaaaaaaaaaaaa.bbb");
        assert_eq!((qtype, partial), (0, true));
        // Nothing read at all is partial too.
        assert!(dns_fields(event(&skb_raw(b""))).2);
        // A compression pointer in a query's own name.
        assert!(dns_fields(event(&skb_raw(b"\x03abc\xc0\x0c"))).2);
    }

    /// R14b: without the worker's decode the event carries no name and is
    /// partial — the core never walks the bytes itself; the `udp_sendmsg`
    /// sensor's type (the kernel's) stays, the socket buffer's is unknown.
    #[test]
    fn without_the_workers_decode_the_event_has_no_name() {
        let skb = skb_raw(b"\x07example\x03com\x00\x00\x10\x00\x01");
        assert_eq!(
            dns_fields(query_event(&skb, None)),
            (String::new(), 0, true)
        );
        let mut sendmsg = DnsQueryRaw::zeroed();
        sendmsg.qtype = 28;
        sendmsg.qname_len = 5;
        sendmsg.query_name[..5].copy_from_slice(b"\x04host");
        assert_eq!(
            dns_fields(query_event(&sendmsg, None)),
            (String::new(), 28, true)
        );
        assert_eq!(nss_query_name(None), None);
        // the request carries the bytes as the kernel copied them
        let q = name_request(&skb);
        assert_eq!(q.form, QnameForm::WireFindEnd);
        assert_eq!(q.bytes.len(), 17);
        let mut nss = DnsQueryRaw::zeroed();
        nss.flags = dns_flags::NSS;
        assert_eq!(name_request(&nss).form, QnameForm::Nss);
        assert_eq!(name_request(&sendmsg).form, QnameForm::Wire);
    }

    #[test]
    fn sendmsg_record_keeps_the_kernel_type() {
        let mut raw = DnsQueryRaw::zeroed();
        raw.qtype = 28;
        let qname = b"\x04host\x00";
        raw.qname_len = 5; // the string read does not count the root label
        raw.query_name[..qname.len()].copy_from_slice(qname);
        assert_eq!(dns_fields(event(&raw)), ("host".into(), 28, false));
    }

    /// Lot 311 (F4): an account whose GECOS is not UTF-8 does not hide the
    /// resolvers' uids (on main the whole file read as empty).
    #[test]
    fn a_latin1_account_does_not_hide_the_resolvers() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("passwd");
        std::fs::write(
            &p,
            b"u:x:1000:1000:J\xe9r\xf4me,,,:/home/u:/bin/bash\n\
              systemd-resolve:x:991:991:systemd Resolver:/:/usr/sbin/nologin\n",
        )
        .unwrap();
        assert_eq!(resolver_uids(&passwd_at(&p)), vec![991]);
    }

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
        let src = include_str!(concat!(env!("NN_REPO_ROOT"), "/agent-ebpf/src/dns_skb.rs"));
        assert!(src.contains(&format!("pub fn {SKB4_PROGRAM}(")));
        assert!(src.contains(&format!("pub fn {SKB6_PROGRAM}(")));
        let old = include_str!(concat!(
            env!("NN_REPO_ROOT"),
            "/agent-ebpf/src/dns_query.rs"
        ));
        assert!(old.contains(&format!("pub fn {SENDMSG_PROGRAM}(")));
    }
}
