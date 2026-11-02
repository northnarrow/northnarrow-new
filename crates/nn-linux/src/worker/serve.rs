//! The worker's side (R14a, plan §3.5): `northnarrow-agent --worker <kind>
//! --ipc-fd 3`.
//!
//! [`main`] runs before anything else of the agent — no logging, no
//! runtime, no configuration: it reads its four arguments, names its
//! thread, enters its sandbox (`crate::sandbox::enter`, exiting with
//! [`EXIT_SANDBOX`] if it cannot), says hello, then answers the core's
//! requests one at a time until the core closes the channel. A request it
//! cannot decode ends it ([`EXIT_PROTOCOL`]): the core sent it, and only a
//! broken core sends that.
//!
//! The answers stay inside the protocol's bounds for any input
//! (`nn_proto::ipc::check_response` accepts them): a hostile input never
//! makes an honest worker look like a lying one.

use std::os::fd::RawFd;

use nn_proto::ipc::{
    alpn_display, decode, encode, Answer, FromWorker, QnameForm, QnameIn, QnameOut, Refusal,
    Request, Response, SniOut, TlsOut, ToWorker, WorkerHello, WorkerKind, IPC_VERSION, MAX_ALPN,
    MAX_FRAME,
};

use super::transport::{self, Recv};
use crate::sandbox;

/// The worker's exit statuses the core tells apart.
pub const EXIT_USAGE: i32 = 64;
/// The core sent what no core sends.
pub const EXIT_PROTOCOL: i32 = 76;
/// The sandbox could not be entered (`EX_CONFIG`).
pub const EXIT_SANDBOX: i32 = 78;

/// What the command line asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub kind: WorkerKind,
    pub ipc_fd: RawFd,
    /// `debug-trigger` builds: the compromised-worker harness's attack
    /// (`--hostile <attack>`, [`super::hostile`]).
    pub hostile: Option<String>,
}

/// Is this process started as a worker? (`argv[1] == "--worker"`.)
pub fn requested(args: &[String]) -> bool {
    args.get(1).map(String::as_str) == Some("--worker")
}

/// `--worker <kind> --ipc-fd <n> [--hostile <attack>]`, exactly.
pub fn parse_args(args: &[String]) -> Result<Args, String> {
    let rest: Vec<&str> = args.iter().skip(1).map(String::as_str).collect();
    let (kind, fd, tail) = match rest.as_slice() {
        ["--worker", kind, "--ipc-fd", fd, tail @ ..] => (*kind, *fd, tail),
        _ => return Err("usage: --worker <kind> --ipc-fd <n>".into()),
    };
    let kind = WorkerKind::from_name(kind).ok_or_else(|| format!("no worker kind `{kind}`"))?;
    let ipc_fd: RawFd = fd.parse().map_err(|_| format!("bad descriptor `{fd}`"))?;
    if !(3..64).contains(&ipc_fd) {
        return Err(format!("descriptor {ipc_fd} out of range"));
    }
    let hostile = match tail {
        [] => None,
        ["--hostile", attack] => Some((*attack).to_string()),
        _ => return Err(format!("unexpected arguments {tail:?}")),
    };
    Ok(Args {
        kind,
        ipc_fd,
        hostile,
    })
}

/// Name the process's thread (`comm`, 15 bytes): `nn-worker-parse`.
fn set_name(kind: WorkerKind) {
    let mut name = [0u8; 16];
    let s = format!("nn-worker-{}", kind.name());
    let n = s.len().min(15);
    name[..n].copy_from_slice(&s.as_bytes()[..n]);
    // SAFETY: PR_SET_NAME with a NUL-terminated 16-byte buffer.
    unsafe { libc::prctl(libc::PR_SET_NAME, name.as_ptr(), 0, 0, 0) };
}

/// The worker's whole life; its exit status.
pub fn main(args: &[String]) -> i32 {
    let a = match parse_args(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("northnarrow worker: {e}");
            return EXIT_USAGE;
        }
    };
    set_name(a.kind);
    #[cfg(feature = "debug-trigger")]
    if let Some(attack) = &a.hostile {
        return super::hostile::run(&a, attack);
    }
    #[cfg(not(feature = "debug-trigger"))]
    if a.hostile.is_some() {
        eprintln!("northnarrow worker: --hostile exists only in lab builds (debug-trigger)");
        return EXIT_USAGE;
    }
    let level = match sandbox::enter(&sandbox::Profile::parse(a.ipc_fd)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "northnarrow worker {}: sandbox not entered: {e}",
                a.kind.name()
            );
            return EXIT_SANDBOX;
        }
    };
    let hello = FromWorker::Hello(WorkerHello {
        version: IPC_VERSION,
        kind: a.kind,
        // SAFETY: getpid has no preconditions (kept by the filter).
        pid: unsafe { libc::getpid() } as u32,
        sandbox: level,
    });
    if let Err(code) = send(a.ipc_fd, &hello) {
        return code;
    }
    serve_loop(a.ipc_fd)
}

fn send(fd: RawFd, msg: &FromWorker) -> Result<(), i32> {
    let bytes = encode(msg).map_err(|e| {
        eprintln!("northnarrow worker: an answer does not fit a frame: {e}");
        EXIT_PROTOCOL
    })?;
    // a closed channel: the core is gone, and so is this worker
    transport::send_to(fd, &bytes).map_err(|_| 0)
}

/// Answer requests until the channel closes.
pub fn serve_loop(fd: RawFd) -> i32 {
    let mut buf = vec![0u8; MAX_FRAME];
    loop {
        let n = match transport::recv_from(fd, &mut buf) {
            Ok(Recv::Packet(n)) => n,
            Ok(Recv::Closed) | Err(_) => return 0,
            Ok(Recv::Empty) => continue,
            Ok(Recv::Refused(v)) => {
                eprintln!("northnarrow worker: {v}");
                return EXIT_PROTOCOL;
            }
        };
        let msg: ToWorker = match decode(&buf[..n]) {
            Ok(m) => m,
            Err(v) => {
                eprintln!("northnarrow worker: {v}");
                return EXIT_PROTOCOL;
            }
        };
        let answer = answer(&msg.req);
        if let Err(code) = send(fd, &FromWorker::Response(Response { id: msg.id, answer })) {
            return code;
        }
    }
}

/// The answer to one request (the parsers run here, and only here).
pub(crate) fn answer(req: &Request) -> Answer {
    if req.check().is_err() {
        return Answer::Refused(Refusal::OutOfBounds);
    }
    match req {
        Request::Ping => Answer::Pong,
        Request::DnsNames(names) => Answer::DnsNames(names.iter().map(qname).collect()),
        Request::TlsClientHello(bytes) => Answer::Tls(tls(bytes)),
        Request::DnsAnswers(bytes) => Answer::DnsAnswers {
            a: nn_parse::dns_records::parse_a_records(bytes)
                .into_iter()
                .map(|ip| ip.octets())
                .collect(),
            aaaa: nn_parse::dns_records::parse_aaaa_records(bytes)
                .into_iter()
                .map(|ip| ip.octets())
                .collect(),
        },
        Request::DebugCrash => debug_crash(),
        Request::DebugHang => debug_hang(),
    }
}

fn qname(q: &QnameIn) -> QnameOut {
    use nn_parse::dns_qname as d;
    match q.form {
        QnameForm::Nss => QnameOut {
            name: d::nss_presentation(&q.bytes),
            end: None,
        },
        QnameForm::Wire => QnameOut {
            name: d::decode_dns_qname(&q.bytes),
            end: None,
        },
        QnameForm::WireFindEnd => QnameOut {
            name: d::decode_dns_qname(&q.bytes),
            end: d::qname_wire_end(&q.bytes).and_then(|e| u16::try_from(e).ok()),
        },
    }
}

fn tls(bytes: &[u8]) -> TlsOut {
    use nn_parse::tls::{self as t, ClientHelloParse};
    match t::parse_client_hello_outcome(bytes) {
        ClientHelloParse::Incomplete => TlsOut::Incomplete,
        ClientHelloParse::Invalid => TlsOut::Invalid,
        ClientHelloParse::Complete(hello) => TlsOut::Complete {
            ja3: t::compute_ja3(&hello),
            ja4: t::compute_ja4(&hello),
            sni: match t::sni(&hello) {
                t::Sni::Absent => SniOut::Absent,
                t::Sni::Host(h) => SniOut::Host(h),
                t::Sni::NonConforming => SniOut::NonConforming,
            },
            // the protocol's bounds: no empty name, printable ASCII
            // (escaped), at most MAX_TLS_FIELD bytes each, MAX_ALPN names
            alpn: t::extract_alpn(&hello)
                .iter()
                .filter(|p| !p.is_empty())
                .map(|p| alpn_display(p.as_bytes()))
                .take(MAX_ALPN)
                .collect(),
        },
    }
}

/// `debug-trigger` builds: the lab's worker crash (an abort: `SIGABRT`).
#[cfg(feature = "debug-trigger")]
fn debug_crash() -> Answer {
    std::process::abort()
}

#[cfg(not(feature = "debug-trigger"))]
fn debug_crash() -> Answer {
    Answer::Refused(Refusal::DebugOnly)
}

/// `debug-trigger` builds: the lab's worker hang — it stops answering
/// (blocked in `recvfrom`, its requests read and dropped) until the core
/// gives up on it and kills it.
#[cfg(feature = "debug-trigger")]
fn debug_hang() -> Answer {
    let mut buf = vec![0u8; MAX_FRAME];
    loop {
        if let Ok(Recv::Closed) | Err(_) = transport::recv_from(super::spawn::IPC_FD, &mut buf) {
            std::process::exit(0);
        }
    }
}

#[cfg(not(feature = "debug-trigger"))]
fn debug_hang() -> Answer {
    Answer::Refused(Refusal::DebugOnly)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nn_proto::ipc::check_response;

    fn argv(s: &str) -> Vec<String> {
        s.split(' ').map(str::to_string).collect()
    }

    #[test]
    fn the_command_line_is_exact() {
        assert!(requested(&argv(
            "northnarrow-agent --worker parse --ipc-fd 3"
        )));
        assert!(!requested(&argv("northnarrow-agent --admin-socket x")));
        assert_eq!(
            parse_args(&argv("x --worker parse --ipc-fd 3")).unwrap(),
            Args {
                kind: WorkerKind::Parse,
                ipc_fd: 3,
                hostile: None
            }
        );
        assert_eq!(
            parse_args(&argv("x --worker parse --ipc-fd 3 --hostile read-keys"))
                .unwrap()
                .hostile
                .as_deref(),
            Some("read-keys")
        );
        for bad in [
            "x --worker export --ipc-fd 3",
            "x --worker parse --ipc-fd 2",
            "x --worker parse --ipc-fd 99",
            "x --worker parse --ipc-fd three",
            "x --worker parse",
            "x --worker parse --ipc-fd 3 --verbose",
            "x --worker parse --ipc-fd 3 --hostile",
            "x --ipc-fd 3 --worker parse",
        ] {
            assert!(parse_args(&argv(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn every_answer_is_inside_the_protocol_for_hostile_inputs() {
        let reqs = [
            Request::Ping,
            Request::DnsNames(vec![
                QnameIn {
                    bytes: b"\x07example\x03com\x00\x00\x01".to_vec(),
                    form: QnameForm::WireFindEnd,
                },
                QnameIn {
                    bytes: vec![0xc0, 0x0c],
                    form: QnameForm::WireFindEnd,
                },
                QnameIn {
                    bytes: vec![0x3f; 300],
                    form: QnameForm::Wire,
                },
                QnameIn {
                    bytes: b"\x03a.\\\x01\xff\x00".to_vec(),
                    form: QnameForm::WireFindEnd,
                },
                QnameIn {
                    bytes: vec![],
                    form: QnameForm::WireFindEnd,
                },
            ]),
            Request::TlsClientHello(vec![0x16, 3, 1, 0, 5, 1, 0, 0, 1, 3]),
            Request::TlsClientHello(vec![0xff; 100]),
            Request::DnsAnswers(vec![0; 12]),
            Request::DnsAnswers(vec![0xff; 4000]),
        ];
        for r in &reqs {
            let a = answer(r);
            assert_eq!(check_response(r, &a), Ok(()), "{r:?} → {a:?}");
        }
        // the decode is nn-parse's
        let Answer::DnsNames(out) = answer(&reqs[1]) else {
            panic!()
        };
        assert_eq!(out[0].name, "example.com");
        assert_eq!(out[0].end, Some(13));
        assert_eq!(out[3].name, "a\\046\\092.\\255");
    }

    /// A ClientHello (one TLS record) with `alpn` ALPN names.
    fn client_hello_with_alpn(alpn: usize) -> Vec<u8> {
        let mut list = Vec::new();
        for i in 0..alpn {
            list.push(1u8);
            list.push(b'a' + (i % 26) as u8);
        }
        let mut ext = Vec::new();
        ext.extend_from_slice(&0x0010u16.to_be_bytes());
        ext.extend_from_slice(&((list.len() + 2) as u16).to_be_bytes());
        ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
        ext.extend_from_slice(&list);
        let mut body = Vec::new();
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend_from_slice(&[0u8; 32]);
        body.push(0); // session id
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.extend_from_slice(&[1, 0]); // compression: null
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut hs = vec![1u8];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    /// More ALPN names than an answer may carry: the worker keeps the
    /// protocol's bound (an honest worker never looks like a lying one).
    #[test]
    fn a_hello_with_too_many_alpn_names_is_answered_within_bounds() {
        let req = Request::TlsClientHello(client_hello_with_alpn(MAX_ALPN + 10));
        let a = answer(&req);
        assert_eq!(check_response(&req, &a), Ok(()), "{a:?}");
        match a {
            Answer::Tls(TlsOut::Complete { alpn, .. }) => assert_eq!(alpn.len(), MAX_ALPN),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_request_out_of_bounds_is_refused_not_parsed() {
        let r = Request::DnsNames(vec![]);
        assert!(matches!(answer(&r), Answer::Refused(_)));
    }

    #[cfg(not(feature = "debug-trigger"))]
    #[test]
    fn a_production_worker_refuses_the_debug_faults() {
        assert!(matches!(answer(&Request::DebugCrash), Answer::Refused(_)));
        assert!(matches!(answer(&Request::DebugHang), Answer::Refused(_)));
    }
}
