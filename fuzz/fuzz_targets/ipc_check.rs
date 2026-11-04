#![no_main]
//! R14a, review of #480 (F1): what a worker sends the core is
//! attacker-controlled by construction — the worker is the process a
//! hostile input may have taken over. Whatever its bytes, the core's
//! `decode`, `check_hello` and `check_response` never panic (a panic in
//! the core is the denial of service the process split exists to
//! prevent), and what they accept keeps the promises the core relies on:
//!
//! - a hello accepted runs under the seccomp filter, `no_new_privs`, not
//!   dumpable, another account than root without groups, no capability,
//!   no core and no process, the kernel's Landlock ABI and every right it
//!   gives;
//! - an answer accepted is the request's kind, never a refusal, one name
//!   per name asked, each in its alphabet and its length, empty only for
//!   bytes that decode to none, an end only where asked and just past a
//!   zero byte; JA3 32 hex digits; JA4 36 ASCII bytes in its
//!   shape; an SNI a host name; ALPN names printable ASCII, non-empty,
//!   bounded; no more DNS answers than the bytes can hold;
//! - a message decoded encodes back to the bytes that decode to itself.
//!
//! The first byte chooses the request an answer is checked against (its
//! two low bits), its size (the next four), a name's form (the two high
//! bits: wire, NSS text, wire with its end asked for), or the kernel's
//! Landlock ABI a hello is checked against; the rest is the worker's
//! packet.
use libfuzzer_sys::fuzz_target;
use nn_proto::ipc::{
    alpn_display, check_hello, check_response, decode, encode, max_qname_out,
    min_dns_answer_bytes, Answer, DnsRecordOut, Expected, MAX_DNS_NAME_OUT, MAX_DNS_RECORDS, FromWorker, QnameForm, QnameIn, Request, SniOut, TlsOut,
    ToWorker, WorkerKind, LANDLOCK_ABI_KNOWN, MAX_ALPN, MAX_TLS_FIELD,
};

fn lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A name's form, from the selector's two high bits.
fn form(sel: u8) -> QnameForm {
    match sel >> 6 {
        1 => QnameForm::Nss,
        2 => QnameForm::WireFindEnd,
        _ => QnameForm::Wire,
    }
}

/// A name's bytes: `len` of them from the selector (its first byte the
/// selector itself, so a root label, a cut label or a long name all occur).
fn name_bytes(sel: u8, len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_add(sel)).collect()
}

/// The request an answer is checked against.
fn request(sel: u8, answer: &Answer) -> Request {
    let size = usize::from(sel >> 2);
    match sel & 3 {
        0 => Request::Ping,
        1 => {
            // as many names as answered, so each one is checked
            let n = match answer {
                Answer::DnsNames(outs) => outs.len(),
                _ => 1,
            };
            Request::DnsNames(
                (0..n)
                    .map(|_| QnameIn {
                        bytes: name_bytes(sel, (size & 0xf) * 8),
                        form: form(sel),
                    })
                    .collect(),
            )
        }
        2 => Request::TlsClientHello(vec![0x16; size]),
        _ => Request::DnsAnswers(vec![0; size * 16]),
    }
}

fn accepted_answer(req: &Request, answer: &Answer) {
    match (req, answer) {
        // review of #481 (R14b-1): never an honest answer to a checked request
        (req, Answer::Refused(r)) => panic!("{} refused ({r}) accepted", req.name()),
        (Request::Ping, Answer::Pong) => {}
        (Request::DnsNames(ins), Answer::DnsNames(outs)) => {
            assert_eq!(ins.len(), outs.len());
            for (i, o) in ins.iter().zip(outs) {
                assert!(o.name.len() <= max_qname_out(i.bytes.len()), "{o:?}");
                let body = o.name.strip_suffix('…').unwrap_or(&o.name);
                assert!(body.bytes().all(|b| (0x20..=0x7e).contains(&b)), "{o:?}");
                assert!(i.form != QnameForm::Nss || !o.name.ends_with('…'), "{o:?}");
                // review of #481 (R14b-1): an empty name only for bytes that
                // decode to none, an end just past a zero byte
                if o.name.is_empty() {
                    assert!(
                        i.bytes.len() < 2 || i.bytes[0] == 0 || i.form == QnameForm::Nss,
                        "{o:?}"
                    );
                }
                if let Some(e) = o.end {
                    assert!(
                        i.form == QnameForm::WireFindEnd && e != 0 && usize::from(e) <= i.bytes.len(),
                        "{o:?}"
                    );
                    assert_eq!(i.bytes[usize::from(e) - 1], 0, "{o:?}");
                }
            }
        }
        (Request::TlsClientHello(_), Answer::Tls(t)) => {
            if let TlsOut::Complete {
                ja3,
                ja4,
                sni,
                alpn,
            } = t
            {
                assert!(lower_hex(ja3, 32), "{ja3:?}");
                let b = ja4.as_bytes();
                assert!(ja4.is_ascii() && b.len() == 36, "{ja4:?}");
                assert!(b[0] == b't' && b[10] == b'_' && b[23] == b'_', "{ja4:?}");
                assert!(lower_hex(&ja4[11..23], 12) && lower_hex(&ja4[24..36], 12), "{ja4:?}");
                if let SniOut::Host(h) = sni {
                    assert!(!h.is_empty() && h.len() <= 253, "{h:?}");
                    assert!(
                        h.bytes().all(|c| c.is_ascii_lowercase()
                            || c.is_ascii_digit()
                            || c == b'-'
                            || c == b'.'),
                        "{h:?}"
                    );
                }
                assert!(alpn.len() <= MAX_ALPN);
                for p in alpn {
                    assert!(!p.is_empty() && p.len() <= MAX_TLS_FIELD, "{p:?}");
                    assert!(p.bytes().all(|c| (0x20..=0x7e).contains(&c)), "{p:?}");
                }
            }
        }
        (Request::DnsAnswers(_), Answer::DnsAnswers(None)) => {}
        // lot 275: the records fit in the bytes, within the bound; every
        // name printable ASCII and bounded
        (Request::DnsAnswers(bytes), Answer::DnsAnswers(Some(out))) => {
            assert!(out.records.len() <= MAX_DNS_RECORDS);
            assert!(min_dns_answer_bytes(&out.records) <= bytes.len());
            assert!(out.rcode <= 15);
            let ok = |n: &str| n.len() <= MAX_DNS_NAME_OUT && n.bytes().all(|b| (0x20..=0x7e).contains(&b));
            assert!(ok(&out.qname), "{out:?}");
            for r in &out.records {
                match r {
                    DnsRecordOut::A { name, .. } | DnsRecordOut::Aaaa { name, .. } => assert!(ok(name)),
                    DnsRecordOut::Cname { name, target, .. } => assert!(ok(name) && ok(target)),
                }
            }
        }
        (req, answer) => panic!("{} accepted {answer:?}", req.name()),
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&sel, packet)) = data.split_first() else {
        return;
    };
    // the worker's own rendering of a raw ALPN name is what the core takes
    let shown = alpn_display(packet);
    assert!(shown.len() <= MAX_TLS_FIELD);
    assert!(shown.bytes().all(|b| (0x20..=0x7e).contains(&b)));
    // the worker's side: a request it decodes is checked without a panic
    if let Ok(m) = decode::<ToWorker>(packet) {
        let _ = m.req.check();
    }
    let Ok(msg) = decode::<FromWorker>(packet) else {
        return;
    };
    if let Ok(again) = encode(&msg) {
        assert_eq!(decode::<FromWorker>(&again).ok().as_ref(), Some(&msg));
    }
    match msg {
        FromWorker::Hello(h) => {
            let want = Expected {
                kind: WorkerKind::Parse,
                pid: h.pid,
                uid: h.sandbox.uid,
                gid: h.sandbox.gid,
                kernel_landlock_abi: sel >> 2,
            };
            if check_hello(&h, &want).is_ok() {
                let s = &h.sandbox;
                assert!(s.seccomp && s.no_new_privs && !s.dumpable, "{s:?}");
                assert!(s.uid != 0 && s.gid != 0 && s.groups == 0, "{s:?}");
                assert_eq!((s.cap_eff, s.cap_prm, s.cap_inh, s.cap_amb), (0, 0, 0, 0));
                assert_eq!((s.core, s.nproc), (0, 0));
                let abi = want.kernel_landlock_abi.min(LANDLOCK_ABI_KNOWN);
                assert_eq!(s.landlock_abi, abi);
                assert!(abi < 1 || s.fs_denied, "{s:?}");
                assert!(abi < 4 || s.net_denied, "{s:?}");
                assert!(abi < 6 || s.scoped, "{s:?}");
            }
        }
        FromWorker::Response(r) => {
            let req = request(sel, &r.answer);
            if check_response(&req, &r.answer).is_ok() {
                accepted_answer(&req, &r.answer);
            }
        }
    }
});
