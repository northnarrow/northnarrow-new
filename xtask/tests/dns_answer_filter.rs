//! Lot 1.4 (plan S1, F8): the DNS response program (`dns_answer`, fexit on
//! `udp_recvmsg` / `udpv6_recvmsg`) runs on every UDP receive of more than
//! 12 bytes. Its port filter comes first and costs no helper call:
//!
//! 1. **A socket connected to another port than 53 is left at once.** A
//!    connected UDP socket receives only from its peer: its peer port
//!    (`skc_dport`) other than 0 (no peer) and 53 means no DNS response.
//!    The datagram's source is read only past that test, from
//!    `msg->msg_name` first and the socket's peer (the port already read)
//!    when there is none — the same answers as before.
//! 2. **The two reads are the hook's own typed arguments.** `skc_dport`
//!    of the `struct sock *` and `msg_name` of the `struct msghdr *` are
//!    plain loads at the compiled offsets — fields the verifier checks
//!    against the kernel's BTF — when the agent resolved those offsets for
//!    the running kernel; at any other, the probe helper at the resolved
//!    one.
//!
//! The behaviour is shown in the lab (`agent/tests/net_privileged_e2e.rs`:
//! a name resolved on an unconnected socket, and on a connected one read
//! with `recv` and with `recvfrom`). Here the code is read; each rule is
//! shown failing on a planted violation.

mod support;

use std::fs;

use support::{matching_brace, repo_root, strip_comments};

const DNS_ANSWER: &str = "agent-ebpf/src/dns_answer.rs";

fn source() -> String {
    fs::read_to_string(repo_root().join(DNS_ANSWER)).unwrap_or_else(|e| panic!("{DNS_ANSWER}: {e}"))
}

/// The body of `fn name` (to its matching brace), or `None`.
fn body<'a>(code: &'a str, name: &str) -> Option<&'a str> {
    let start = code.find(&format!("fn {name}("))?;
    let open = start + code[start..].find('{')?;
    Some(&code[open..open + matching_brace(&code[open..])])
}

/// `needles` all in `hay`, in this order; the first missing one otherwise.
fn in_order<'n>(hay: &str, needles: &[&'n str]) -> Result<(), &'n str> {
    let mut at = 0;
    for n in needles {
        match hay[at..].find(n) {
            Some(i) => at += i + n.len(),
            None => return Err(n),
        }
    }
    Ok(())
}

/// The rules on `dns_answer.rs`'s text (comments blanked).
fn violations(text: &str) -> Vec<String> {
    let code = strip_comments(text);
    let mut out = Vec::new();
    if !code.contains("const DNS_PORT_BE: u16 = 0x3500;") {
        out.push("DNS_PORT_BE is not 53 in network byte order".to_string());
    }
    // 1. the filter first, then the source as before
    match body(&code, "try_answer") {
        None => out.push("no fn try_answer".to_string()),
        Some(b) => {
            if let Err(n) = in_order(
                b,
                &[
                    "if ret <= DNS_HDR_LEN {",
                    "if msg_ptr.is_null() {",
                    "let peer = peer_port(sk_ptr);",
                    "if peer != 0 && peer != DNS_PORT_BE {\n            return;\n        }",
                    "let src = match source_from_name(msg_ptr) {",
                    "Src::NotDns => return,",
                    "Src::NoName => match source_from_sock(sk_ptr, peer) {",
                    "admit(",
                    "DNS_ANSWER_EVENTS.reserve::<DnsAnswerRaw>(0)",
                ],
            ) {
                out.push(format!("try_answer: {n:?} missing or out of order"));
            }
            if b.matches("peer_port(").count() != 1 {
                out.push("try_answer reads the peer port more than once".to_string());
            }
        }
    }
    match body(&code, "source_from_sock") {
        None => out.push("no fn source_from_sock".to_string()),
        Some(b) => {
            if b.contains("SOCK_SKC_DPORT_OFFSET") || !b.contains("if port_be != DNS_PORT_BE {") {
                out.push("source_from_sock does not judge the port it is given".to_string());
            }
        }
    }
    match body(&code, "source_from_name") {
        None => out.push("no fn source_from_name".to_string()),
        Some(b) => {
            if let Err(n) = in_order(
                b,
                &[
                    "let name = msg_name(msg_ptr);",
                    "if family != AF_INET && family != AF_INET6 {",
                    "if port_be != DNS_PORT_BE {",
                ],
            ) {
                out.push(format!("source_from_name: {n:?} missing or out of order"));
            }
        }
    }
    // 2. the typed loads at the compiled offset, the helper at another
    for (f, slot, ty, fallback) in [
        (
            "peer_port",
            "SOCK_SKC_DPORT_OFFSET",
            "*const u16",
            "bpf_probe_read_kernel::<u16>(sk_ptr.add(at) as *const u16).unwrap_or(0)",
        ),
        (
            "msg_name",
            "MSGHDR_NAME_OFFSET",
            "*const *const u8",
            "bpf_probe_read_kernel::<*const u8>(msg_ptr.add(at) as *const *const u8)\
             .unwrap_or(core::ptr::null())",
        ),
    ] {
        let Some(b) = body(&code, f) else {
            out.push(format!("no fn {f}"));
            continue;
        };
        let flat: String = b.split_whitespace().collect::<Vec<_>>().join(" ");
        let arg = if f == "peer_port" {
            "sk_ptr"
        } else {
            "msg_ptr"
        };
        let direct = format!("core::ptr::read_volatile({arg}.add({slot}) as {ty})");
        if let Err(n) = in_order(
            &flat,
            &[
                &format!("let at = off!({slot});"),
                &format!("if at == {slot} {{"),
                &direct,
                "} else {",
                fallback,
            ],
        ) {
            out.push(format!("{f}: {n:?} missing or out of order"));
        }
        if flat.matches("read_volatile(").count() != 1 {
            out.push(format!(
                "{f}: a plain load other than at the compiled offset"
            ));
        }
    }
    out
}

#[test]
fn the_dns_response_program_filters_by_port_first_without_a_helper() {
    let v = violations(&source());
    assert!(v.is_empty(), "{v:#?}");
}

#[test]
fn a_filter_out_of_place_or_a_load_at_another_offset_fails_the_ratchet() {
    let real = source();
    let plants: [(&str, &str, &str); 6] = [
        // the filter dropped: every receive reads the datagram's source
        (
            "        if peer != 0 && peer != DNS_PORT_BE {\n            return;\n        }\n",
            "",
            "try_answer",
        ),
        // a socket with no peer taken for one connected elsewhere
        (
            "if peer != 0 && peer != DNS_PORT_BE {",
            "if peer != DNS_PORT_BE {",
            "try_answer",
        ),
        // the socket path reading the port again, not the one tested
        (
            "Src::NoName => match source_from_sock(sk_ptr, peer) {",
            "Src::NoName => match source_from_sock(sk_ptr, 0) {",
            "try_answer",
        ),
        // a plain load at the resolved (unknown to the verifier) offset
        (
            "core::ptr::read_volatile(sk_ptr.add(SOCK_SKC_DPORT_OFFSET) as *const u16)",
            "core::ptr::read_volatile(sk_ptr.add(at) as *const u16)",
            "peer_port",
        ),
        // no fallback to the helper on another layout
        (
            "bpf_probe_read_kernel::<*const u8>(msg_ptr.add(at) as *const *const u8).unwrap_or(core::ptr::null())",
            "core::ptr::read_volatile(msg_ptr.add(at) as *const *const u8)",
            "msg_name",
        ),
        // msg_name read past the source's port
        (
            "let name = msg_name(msg_ptr);",
            "let name = core::ptr::null::<u8>();",
            "source_from_name",
        ),
    ];
    for (from, to, why) in plants {
        assert!(real.contains(from), "the plant's text is gone: {from:?}");
        let v = violations(&real.replacen(from, to, 1));
        assert!(
            v.iter().any(|m| m.starts_with(why)),
            "planted {from:?} -> {to:?}: wanted {why:?}, got {v:#?}"
        );
    }
}
