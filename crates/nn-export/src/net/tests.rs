//! The syslog sink against receivers of every kind, in-process: an honest
//! one, one that drops the connection, one that never reads, one that never
//! speaks, one that speaks garbage, one with another CA's certificate, none
//! at all. Every request returns within its budget; every row is delivered
//! at least once, in order, through the failures.

use super::*;
use crate::syslog::FrameReader;
use crate::tls::tests::{CA_PEM, OTHER_CA_PEM, SRV_KEY, SRV_PEM};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Honest,
    /// Close each of its first `n` connections after one message.
    DropFirst(usize),
    /// Complete the handshake on each of its first `n` connections, read
    /// nothing for `ms`, then close — the bytes the kernel acknowledged
    /// unread: a reset.
    CloseUnread(usize, u64),
    /// Complete the handshake, then never read.
    NoRead,
    /// NoRead with a receive buffer of a few KiB: its kernel acknowledges
    /// no more than that.
    NoReadTiny,
    /// Accept, never say anything.
    Silent,
    /// Answer the ClientHello with bytes that are not TLS.
    Garbage,
    /// Send application data.
    Chatty,
}

struct Receiver {
    addr: SocketAddr,
    got: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: Arc<AtomicBool>,
}

impl Drop for Receiver {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
    }
}

fn server_config() -> Arc<rustls::ServerConfig> {
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(SRV_PEM.as_bytes())
        .map(Result::unwrap)
        .collect();
    let key = PrivateKeyDer::from_pem_slice(SRV_KEY.as_bytes()).unwrap();
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap(),
    )
}

fn receiver(mode: Mode) -> Receiver {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    if mode == Mode::NoReadTiny {
        use std::os::fd::AsRawFd;
        let n: libc::c_int = 4096;
        // SAFETY: setsockopt of an int on our own listening socket; the
        // connections it accepts inherit the buffer.
        let rc = unsafe {
            libc::setsockopt(
                l.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                (&n as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        assert_eq!(rc, 0);
    }
    let addr = l.local_addr().unwrap();
    let got = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let (g, st) = (Arc::clone(&got), Arc::clone(&stop));
    std::thread::spawn(move || {
        let cfg = server_config();
        let mut conns = 0usize;
        let mut held = Vec::new();
        for s in l.incoming() {
            if st.load(Ordering::SeqCst) {
                return;
            }
            let Ok(mut tcp) = s else { continue };
            conns += 1;
            match mode {
                Mode::Silent => {
                    held.push(tcp);
                    continue;
                }
                Mode::Garbage => {
                    let _ = tcp.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
                    held.push(tcp);
                    continue;
                }
                _ => {}
            }
            let g = Arc::clone(&g);
            let cfg = Arc::clone(&cfg);
            let st = Arc::clone(&st);
            std::thread::spawn(move || {
                let conn = rustls::ServerConnection::new(cfg).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, tcp);
                if let Mode::CloseUnread(k, ms) = mode {
                    if conns <= k {
                        while tls.conn.is_handshaking() {
                            if tls.conn.complete_io(&mut tls.sock).is_err() {
                                return;
                            }
                        }
                        std::thread::sleep(Duration::from_millis(ms));
                        return; // closed with what it did not read
                    }
                }
                if matches!(mode, Mode::NoRead | Mode::NoReadTiny) {
                    // the handshake only
                    while tls.conn.is_handshaking() {
                        if tls.conn.complete_io(&mut tls.sock).is_err() {
                            return;
                        }
                    }
                    while !st.load(Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    return;
                }
                if mode == Mode::Chatty {
                    let _ = tls.write_all(&[b'x'; 8192]);
                    let _ = tls.flush();
                }
                let mut fr = FrameReader::default();
                let mut buf = [0u8; 16384];
                loop {
                    let n = match tls.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    fr.push(&buf[..n]);
                    while let Ok(Some(m)) = fr.next_message() {
                        g.lock().unwrap().push(m);
                        if let Mode::DropFirst(k) = mode {
                            if conns <= k {
                                return; // drops the connection
                            }
                        }
                    }
                }
            });
        }
    });
    Receiver { addr, got, stop }
}

fn quick() -> Limits {
    Limits {
        connect: Duration::from_millis(500),
        handshake: Duration::from_millis(400),
        stall: Duration::from_millis(600),
        ack_wait: Duration::from_millis(50),
        settle: Duration::from_millis(100),
        ..Limits::default()
    }
}

fn sink(addr: SocketAddr, ca: &str, name: &str) -> SyslogSink {
    SyslogSink::new(addr, name, ca.as_bytes())
        .unwrap()
        .with_limits(quick())
}

type R = (u64, u64);

fn framed(r: &R) -> Framed {
    let msg = format!("<110>1 - h northnarrow - t - row {}/{}", r.0, r.1);
    Framed {
        frames: vec![crate::syslog::frame(msg.as_bytes())],
        records: 1,
        verified: r.1.is_multiple_of(2),
    }
}

/// What the core does: send the rows after the last one committed (from
/// its cursor when that goes back), move its cursor to the acked one; each
/// request within its budget. The rows are `(1, l)`, `l` from 1: a row's
/// line is its index plus one.
fn run_core(
    s: &mut SyslogSink,
    rows: &[R],
    budget: Duration,
    tries: usize,
) -> (usize, Vec<Delivered>) {
    run_batches(s, rows, budget, tries, usize::MAX)
}

fn run_batches(
    s: &mut SyslogSink,
    rows: &[R],
    budget: Duration,
    tries: usize,
    batch: usize,
) -> (usize, Vec<Delivered>) {
    let mut acked = 0usize;
    let mut next = 0usize;
    let mut answers = Vec::new();
    for _ in 0..tries {
        if acked == rows.len() {
            break;
        }
        let t0 = Instant::now();
        let slice = &rows[next..rows.len().min(next.saturating_add(batch))];
        let d = s.rows(ExportChain::Detections, slice, |r| *r, framed, t0 + budget);
        assert!(
            t0.elapsed() <= budget + Duration::from_millis(150),
            "a request took {:?} of a {budget:?} budget",
            t0.elapsed()
        );
        if std::env::var_os("NN_EXPORT_TEST_TRACE").is_some() {
            eprintln!("{d:?} {:?} acked {acked} next {next}", s.stats);
        }
        let before = acked;
        if let Some(a) = d.acked {
            assert!(a.1 as usize >= acked, "an ack never goes back");
            acked = a.1 as usize;
        }
        next = d.committed.map_or(acked, |c| c.1 as usize).max(acked);
        assert!(next <= rows.len());
        if d.state == SinkState::Down {
            std::thread::sleep(Duration::from_millis(u64::from(d.retry_ms).min(1500)));
        } else if acked == before {
            std::thread::sleep(Duration::from_millis(20));
        }
        answers.push(d);
    }
    (acked, answers)
}

fn rows(n: u64) -> Vec<R> {
    (1..=n).map(|l| (1, l)).collect()
}

fn texts(r: &Receiver) -> Vec<String> {
    r.got
        .lock()
        .unwrap()
        .iter()
        .map(|m| {
            String::from_utf8_lossy(m)
                .rsplit(' ')
                .next()
                .unwrap()
                .to_string()
        })
        .collect()
}

#[test]
fn an_honest_receiver_gets_every_row_once_in_order() {
    let r = receiver(Mode::Honest);
    let mut s = sink(r.addr, CA_PEM, "receiver.lab");
    let all = rows(40);
    let (done, answers) = run_core(&mut s, &all, Duration::from_millis(800), 60);
    assert_eq!(done, 40, "{answers:?}");
    std::thread::sleep(Duration::from_millis(100));
    let got = texts(&r);
    let want: Vec<String> = all.iter().map(|(f, l)| format!("{f}/{l}")).collect();
    assert_eq!(got, want);
    // the records and the unverified rows are reported once each
    assert_eq!(answers.iter().map(|a| a.records).sum::<u32>(), 40);
    assert_eq!(answers.iter().map(|a| a.unverified).sum::<u32>(), 20);
    assert_eq!(s.stats.sessions, 1);
    assert_eq!(s.now_state(), SinkState::Up);
    // by the IP literal too: the certificate names 127.0.0.1
    let mut by_ip = sink(r.addr, CA_PEM, "127.0.0.1");
    assert_eq!(
        run_core(&mut by_ip, &rows(2), Duration::from_millis(800), 30).0,
        2
    );
}

#[test]
fn a_dropped_connection_loses_nothing() {
    let r = receiver(Mode::DropFirst(2));
    let mut s = sink(r.addr, CA_PEM, "receiver.lab");
    let all = rows(30);
    let (done, answers) = run_core(&mut s, &all, Duration::from_millis(800), 80);
    assert_eq!(done, 30, "{answers:?}");
    std::thread::sleep(Duration::from_millis(100));
    let got = texts(&r);
    for (f, l) in &all {
        assert!(got.contains(&format!("{f}/{l}")), "row {l} lost: {got:?}");
    }
    assert!(
        s.stats.resets >= 1 && s.stats.connects >= 3,
        "{:?}",
        s.stats
    );
    assert!(answers
        .iter()
        .any(|a| matches!(a.fault, Some(SinkFault::Closed) | Some(SinkFault::Io(_)))));
}

/// The settle: a receiver that closes with bytes its kernel acknowledged
/// and it never read resets the connection — those rows were not
/// delivered, and are written again (TCP's acknowledgement alone would
/// have lost them).
#[test]
fn rows_acknowledged_but_unread_are_written_again() {
    let r = receiver(Mode::CloseUnread(1, 30));
    let mut s = sink(r.addr, CA_PEM, "receiver.lab");
    let all = rows(30);
    let (done, answers) = run_core(&mut s, &all, Duration::from_millis(800), 80);
    assert_eq!(done, 30, "{answers:?}");
    std::thread::sleep(Duration::from_millis(100));
    let got = texts(&r);
    for (f, l) in &all {
        assert!(got.contains(&format!("{f}/{l}")), "row {l} lost: {got:?}");
    }
    assert!(s.stats.connects >= 2, "{:?}", s.stats);
}

#[test]
fn a_receiver_that_does_not_read_costs_only_the_budget() {
    let r = receiver(Mode::NoRead);
    let mut s = sink(r.addr, CA_PEM, "receiver.lab").with_limits(Limits {
        in_flight: 64 * 1024,
        ..quick()
    });
    // large rows: the window fills
    let big = |r: &R| Framed {
        frames: vec![crate::syslog::frame(&vec![b'a'; 16 * 1024 + r.1 as usize])],
        records: 1,
        verified: true,
    };
    let all = rows(4000);
    let t0 = Instant::now();
    let mut stalled = false;
    let (mut acked, mut next) = (0usize, 0usize);
    // the bytes written and not acknowledged, at most the bound and the row
    // that passed it
    let mut most = 0usize;
    for _ in 0..80 {
        let t = Instant::now();
        let d = s.rows(
            ExportChain::Netflow,
            &all[next..all.len().min(next + 64)],
            |r| *r,
            big,
            t + Duration::from_millis(200),
        );
        assert!(
            t.elapsed() < Duration::from_millis(400),
            "{:?}",
            t.elapsed()
        );
        if let Some(c) = s.conn.as_ref() {
            most = most.max(c.in_flight);
        }
        if let Some(a) = d.acked {
            acked = a.1 as usize;
        }
        next = d.committed.map_or(acked, |c| c.1 as usize).max(acked);
        if d.fault == Some(SinkFault::Io(libc::ETIMEDOUT)) {
            stalled = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    assert!(stalled, "the stall was seen within {:?}", t0.elapsed());
    assert!(
        (64 * 1024..64 * 1024 + 21 * 1024).contains(&most),
        "in flight at most {most}"
    );
    // what its kernel took settled; the rest is written again elsewhere
    assert!(acked < all.len());
    assert_eq!(s.now_state(), SinkState::Down);
}

/// Rows the core sends again (from its cursor, before their
/// acknowledgement) that this connection already carries are not written
/// twice — the last one committed included.
#[test]
fn rows_sent_again_on_the_same_connection_are_not_written_twice() {
    let r = receiver(Mode::Honest);
    let mut s = sink(r.addr, CA_PEM, "receiver.lab");
    let all = rows(10);
    for _ in 0..3 {
        let t = Instant::now();
        let d = s.rows(
            ExportChain::Detections,
            &all,
            |r| *r,
            framed,
            t + Duration::from_millis(300),
        );
        assert_eq!(d.committed, Some((1, 10)), "{d:?}");
    }
    std::thread::sleep(Duration::from_millis(200));
    let want: Vec<String> = all.iter().map(|(f, l)| format!("{f}/{l}")).collect();
    assert_eq!(texts(&r), want);
}

/// A record larger than rustls' default buffer (64 KiB) is delivered: its
/// write does not fail (it did, as a `Closed`, before lot 276's mutations).
#[test]
fn a_large_record_is_delivered() {
    let r = receiver(Mode::Honest);
    let mut s = sink(r.addr, CA_PEM, "receiver.lab");
    let big = |r: &R| Framed {
        frames: vec![crate::syslog::frame(&vec![b'a'; 200 * 1024 + r.1 as usize])],
        records: 1,
        verified: true,
    };
    let all = rows(6);
    let mut acked = 0usize;
    for _ in 0..40 {
        let t = Instant::now();
        let d = s.rows(
            ExportChain::Netflow,
            &all[acked..],
            |r| *r,
            big,
            t + Duration::from_millis(400),
        );
        assert_eq!(d.fault, None, "{d:?}");
        if let Some(a) = d.acked {
            acked = a.1 as usize;
        }
        if acked == all.len() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(acked, all.len());
    std::thread::sleep(Duration::from_millis(100));
    let got = r.got.lock().unwrap();
    assert_eq!(got.len(), 6);
    assert!(got
        .iter()
        .enumerate()
        .all(|(i, m)| m.len() == 200 * 1024 + i + 1));
}

/// A row is delivered once the receiver's kernel acknowledged its last
/// byte, never because it left this socket: a receiver whose buffer holds
/// less than a row gets none of them counted, however long the connection
/// stays up before its stall.
#[test]
fn a_row_counts_only_once_its_bytes_are_acknowledged() {
    let r = receiver(Mode::NoReadTiny);
    let mut s = sink(r.addr, CA_PEM, "receiver.lab");
    let big = |r: &R| Framed {
        frames: vec![crate::syslog::frame(&vec![b'a'; 64 * 1024 + r.1 as usize])],
        records: 1,
        verified: true,
    };
    let all = rows(32);
    let mut next = 0usize;
    let mut stalled = false;
    for _ in 0..60 {
        let t = Instant::now();
        let d = s.rows(
            ExportChain::Netflow,
            &all[next..],
            |r| *r,
            big,
            t + Duration::from_millis(200),
        );
        if std::env::var_os("NN_EXPORT_TEST_TRACE").is_some() {
            eprintln!("{d:?} {:?}", s.stats);
        }
        assert_eq!(d.acked, None, "a row counted that its receiver never took");
        next = d.committed.map_or(0, |c| c.1 as usize);
        if d.fault == Some(SinkFault::Io(libc::ETIMEDOUT)) {
            stalled = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    assert!(stalled);
}

#[test]
fn silent_garbage_and_chatty_receivers_fail_fast() {
    for (mode, want) in [
        (Mode::Silent, SinkFault::HandshakeTimeout),
        (
            Mode::Garbage,
            SinkFault::Tls(nn_proto::ipc::TlsFault::Protocol),
        ),
    ] {
        let r = receiver(mode);
        let mut s = sink(r.addr, CA_PEM, "receiver.lab").with_limits(Limits {
            peer_bytes: 1024,
            ..quick()
        });
        let all = rows(3);
        let (_, answers) = run_core(&mut s, &all, Duration::from_millis(300), 12);
        assert!(
            answers.iter().any(|a| a.fault == Some(want)),
            "{mode:?}: {answers:?}"
        );
    }
}

/// A receiver that sends application data (more than TLS' own messages)
/// loses its connection; what it had acknowledged stays delivered.
#[test]
fn a_chatty_receiver_is_dropped() {
    let r = receiver(Mode::Chatty);
    let mut s = sink(r.addr, CA_PEM, "receiver.lab").with_limits(Limits {
        peer_bytes: 1024,
        ..quick()
    });
    let all = rows(40);
    let (_, answers) = run_batches(&mut s, &all, Duration::from_millis(300), 30, 2);
    assert!(
        answers.iter().any(|a| a.fault == Some(SinkFault::PeerData)),
        "{answers:?}"
    );
}

#[test]
fn the_receiver_is_authenticated() {
    let r = receiver(Mode::Honest);
    // trusting another CA
    let mut s = sink(r.addr, OTHER_CA_PEM, "receiver.lab");
    let (done, answers) = run_core(&mut s, &rows(2), Duration::from_millis(500), 3);
    assert_eq!(done, 0);
    assert!(answers
        .iter()
        .any(|a| a.fault == Some(SinkFault::Tls(nn_proto::ipc::TlsFault::Certificate))));
    assert_eq!(s.stats.sessions, 0);
    // another name
    let mut s = sink(r.addr, CA_PEM, "other.lab");
    let (done, answers) = run_core(&mut s, &rows(2), Duration::from_millis(500), 3);
    assert_eq!(done, 0);
    assert!(answers
        .iter()
        .any(|a| a.fault == Some(SinkFault::Tls(nn_proto::ipc::TlsFault::Certificate))));
    assert!(r.got.lock().unwrap().is_empty(), "nothing sent to it");
}

#[test]
fn no_receiver_means_down_with_a_backoff() {
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let mut s = sink(addr, CA_PEM, "receiver.lab");
    let t = Instant::now();
    let d = s.rows(
        ExportChain::Actions,
        &rows(2),
        |r| *r,
        framed,
        t + Duration::from_millis(300),
    );
    assert_eq!(d.fault, Some(SinkFault::Connect(libc::ECONNREFUSED)));
    assert_eq!(d.state, SinkState::Down);
    assert!((900..=1001).contains(&d.retry_ms), "{}", d.retry_ms);
    let tried = s.stats.connects;
    assert!(tried <= 1);
    // within the backoff nothing is tried
    let d = s.rows(
        ExportChain::Actions,
        &rows(2),
        |r| *r,
        framed,
        Instant::now() + Duration::from_millis(300),
    );
    assert_eq!(s.stats.connects, tried, "no attempt within the backoff");
    assert_eq!(d.state, SinkState::Down);
    assert_eq!((d.acked, d.committed), (None, None));
}

#[test]
fn a_connection_closes_once_it_carried_its_share() {
    let r = receiver(Mode::Honest);
    let mut s = sink(r.addr, CA_PEM, "receiver.lab").with_limits(Limits {
        connection_bytes: 2000,
        ..quick()
    });
    let all = rows(60);
    let (done, _) = run_batches(&mut s, &all, Duration::from_millis(800), 200, 5);
    assert_eq!(done, 60);
    assert!(s.stats.sessions >= 2, "{:?}", s.stats);
    assert_eq!(s.stats.resets, 0, "a planned close is no failure");
}

#[test]
fn backoff_doubles_to_its_ceiling() {
    assert_eq!(
        (1..=8).map(|f| backoff(f).as_secs()).collect::<Vec<_>>(),
        vec![1, 2, 4, 8, 16, 32, 60, 60]
    );
    assert_eq!(backoff(0).as_secs(), 1);
    assert_eq!(backoff(u32::MAX), MAX_BACKOFF);
}
