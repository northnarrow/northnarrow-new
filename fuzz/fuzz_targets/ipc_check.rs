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
//! - a message decoded encodes back to the bytes that decode to itself;
//! - lot 276, the export worker's answers: rows acknowledged never past
//!   those committed, committed never past the last row sent, a file's
//!   write never in flight, no more unverified rows than records, a sink
//!   asked for never off, a retry bounded; a setup that asked for the pin
//!   either pinned or failed for it; its hello without TCP denied but with
//!   no filesystem rule other than its directory's.
//!
//! The first byte chooses the request an answer is checked against (its
//! two low bits), its size (the next four), a name's form (the two high
//! bits: wire, NSS text, wire with its end asked for), or the kernel's
//! Landlock ABI a hello is checked against; the rest is the worker's
//! packet.
use libfuzzer_sys::fuzz_target;
use nn_proto::ipc::{
    alpn_display, check_hello, check_response, decode, encode, max_qname_out,
    min_dns_answer_bytes, Answer, DnsRecordOut, ExportAddr, ExportChain, ExportRow, ExportRows,
    ExportSetup, ExportSink, Expected, FileSetup, FromWorker, QnameForm, QnameIn, Request,
    SinkFault, SinkState, SniOut, SyslogSetup, TlsOut, ToWorker, WorkerKind, LANDLOCK_ABI_KNOWN,
    MAX_ALPN, MAX_DNS_NAME_OUT, MAX_DNS_RECORDS, MAX_RETRY_MS, MAX_TLS_FIELD,
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

/// Lot 276: the export's request an export answer is checked against —
/// 1 to 16 rows of one chain to the file or the syslog sink, a setup with
/// either sink and the pin asked for or not (the selector's bits).
fn export_request(sel: u8, answer: &Answer) -> Option<Request> {
    match answer {
        Answer::ExportRows(_) => {
            let n = u64::from(sel >> 4) + 1;
            Some(Request::ExportRows(ExportRows {
                sink: if sel & 4 == 0 {
                    ExportSink::File
                } else {
                    ExportSink::Syslog
                },
                chain: if sel & 8 == 0 {
                    ExportChain::Detections
                } else {
                    ExportChain::CanaryAccess
                },
                rows: (1..=n)
                    .map(|l| ExportRow {
                        file: if sel & 8 == 0 { 1 + (l > 8) as u64 } else { 0 },
                        line: l,
                        end: 100 * l,
                        raw: b"{}".to_vec(),
                        rotate: None,
                    })
                    .collect(),
                budget_ms: 1000,
            }))
        }
        Answer::ExportSetup(_) => Some(Request::ExportSetup(ExportSetup {
            agent_id: "0".repeat(32),
            hostname: "host".into(),
            version: "1".into(),
            pubkey: [0; 32],
            file: (sel & 4 != 0).then_some(FileSetup {
                max_bytes: 1 << 20,
                max_files: 2,
            }),
            syslog: (sel & 8 != 0 || sel & 4 == 0).then(|| SyslogSetup {
                addr: ExportAddr::V4([127, 0, 0, 1]),
                port: 6514,
                server_name: "receiver.lab".into(),
                ca_pem: b"-".to_vec(),
                facility: 13,
                pin_port: sel & 16 != 0,
            }),
        })),
        _ => None,
    }
}

/// The request an answer is checked against.
fn request(sel: u8, answer: &Answer) -> Request {
    if let Some(r) = export_request(sel, answer) {
        return r;
    }
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
        // name printable ASCII and bounded. External bug hunt (edition
        // 1.2), BUG02: the floor is the parser's (`dns_records`): an owner
        // and a CNAME's target of one byte, the root's name — a floor of a
        // 2-byte owner refused the honest worker's answer to a root-owned
        // record, and killed it as a violator
        (Request::DnsAnswers(bytes), Answer::DnsAnswers(Some(out))) => {
            assert!(out.records.len() <= MAX_DNS_RECORDS);
            let least = 12
                + 5
                + out
                    .records
                    .iter()
                    .map(|r| match r {
                        DnsRecordOut::A { .. } => 1 + 10 + 4,
                        DnsRecordOut::Aaaa { .. } => 1 + 10 + 16,
                        DnsRecordOut::Cname { .. } => 1 + 10 + 1,
                    })
                    .sum::<usize>();
            assert_eq!(min_dns_answer_bytes(&out.records), least);
            assert!(least <= bytes.len());
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
        (Request::ExportRows(r), Answer::ExportRows(o)) => {
            let last = r.rows.last().map(|x| x.pos());
            if let Some(a) = o.acked {
                assert!(o.committed.is_some_and(|c| a <= c), "{o:?}");
            }
            if let Some(c) = o.committed {
                assert!(last.is_some_and(|l| c <= l), "{o:?}");
            }
            assert!(r.sink != ExportSink::File || o.acked == o.committed, "{o:?}");
            assert!(o.unverified <= o.records, "{o:?}");
            assert!(o.state != SinkState::Off, "{o:?}");
            assert!(o.retry_ms <= MAX_RETRY_MS, "{o:?}");
        }
        (Request::ExportSetup(s), Answer::ExportSetup(o)) => {
            if s.syslog.as_ref().is_some_and(|y| y.pin_port) && !o.port_pinned {
                assert!(
                    o.fault == Some(SinkFault::Pin) && o.syslog == SinkState::Failed,
                    "{o:?}"
                );
            }
            assert_eq!(s.file.is_none(), o.file == SinkState::Off, "{o:?}");
            assert_eq!(s.syslog.is_none(), o.syslog == SinkState::Off, "{o:?}");
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
            // lot 276: the selector's low bit, the export worker's hello
            let kind = if sel & 1 == 0 {
                WorkerKind::Parse
            } else {
                WorkerKind::Export
            };
            let want = Expected {
                kind,
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
                assert!(abi < 4 || kind == WorkerKind::Export || s.net_denied, "{s:?}");
                assert!(
                    s.fs_rules.iter().all(|r| kind.fs_rules().contains(&r.as_str())),
                    "{s:?}"
                );
                assert!(abi > 0 || s.fs_rules.is_empty(), "{s:?}");
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
