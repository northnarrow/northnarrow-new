//! Lot 276's lab receiver: syslog over TLS (RFC 5425), in Rust, on our own
//! lab guests only (`deploy/lab/export/export-lab.sh`). Never shipped: an
//! example of nn-export, built in the guest's tree.
//!
//! `syslog_receiver --listen 127.0.0.1:6514 --cert srv.pem --key srv.key
//! --out capture.log [--mode honest|stall|silent|garbage|slow|chatty]`
//!
//! - honest: every message appended to `--out` as one line (flushed);
//! - stall: the TLS session made, then nothing read (the window fills);
//! - silent: the TCP connection accepted, no TLS spoken;
//! - garbage: bytes that are not TLS answer the ClientHello;
//! - slow: 512 bytes read a second;
//! - chatty: application data sent to the client.
//!
//! Each connection's start and end go to stderr with the messages it gave.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nn_export::syslog::FrameReader;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    Honest,
    Stall,
    Silent,
    Garbage,
    Slow,
    Chatty,
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let listen = arg(&args, "--listen").unwrap_or_else(|| "127.0.0.1:6514".into());
    let cert = arg(&args, "--cert").expect("--cert");
    let key = arg(&args, "--key").expect("--key");
    let out = arg(&args, "--out").expect("--out");
    let mode = match arg(&args, "--mode").as_deref().unwrap_or("honest") {
        "honest" => Mode::Honest,
        "stall" => Mode::Stall,
        "silent" => Mode::Silent,
        "garbage" => Mode::Garbage,
        "slow" => Mode::Slow,
        "chatty" => Mode::Chatty,
        m => panic!("no mode {m}"),
    };
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&cert)
        .expect("cert")
        .map(Result::unwrap)
        .collect();
    let key = PrivateKeyDer::from_pem_file(&key).expect("key");
    let cfg = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap(),
    );
    let sink = Arc::new(Mutex::new(
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&out)
            .expect("--out"),
    ));
    let l = TcpListener::bind(&listen).expect("listen");
    eprintln!("receiver: listening on {listen}, mode {mode:?}, to {out}");
    let mut held: Vec<TcpStream> = Vec::new();
    for (n, s) in l.incoming().enumerate() {
        let Ok(mut tcp) = s else { continue };
        eprintln!("receiver: connection {n} from {:?}", tcp.peer_addr().ok());
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
        let cfg = Arc::clone(&cfg);
        let sink = Arc::clone(&sink);
        std::thread::spawn(move || serve(n, tcp, cfg, sink, mode));
    }
}

fn serve(
    n: usize,
    tcp: TcpStream,
    cfg: Arc<rustls::ServerConfig>,
    sink: Arc<Mutex<std::fs::File>>,
    mode: Mode,
) {
    let conn = rustls::ServerConnection::new(cfg).unwrap();
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    while tls.conn.is_handshaking() {
        if let Err(e) = tls.conn.complete_io(&mut tls.sock) {
            eprintln!("receiver: connection {n}: handshake: {e}");
            return;
        }
    }
    if mode == Mode::Stall {
        eprintln!("receiver: connection {n}: stalled (never read)");
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }
    if mode == Mode::Chatty {
        let _ = tls.write_all(&[b'x'; 128 * 1024]);
        let _ = tls.flush();
    }
    let mut fr = FrameReader::default();
    let mut buf = vec![0u8; if mode == Mode::Slow { 512 } else { 64 * 1024 }];
    let mut msgs = 0u64;
    loop {
        let got = match tls.read(&mut buf) {
            Ok(0) => break,
            Ok(k) => k,
            Err(e) => {
                eprintln!("receiver: connection {n}: {e}");
                break;
            }
        };
        fr.push(&buf[..got]);
        let mut lines = Vec::new();
        loop {
            match fr.next_message() {
                Ok(Some(m)) => {
                    lines.extend_from_slice(&m);
                    lines.push(b'\n');
                    msgs += 1;
                }
                Ok(None) => break,
                Err(e) => {
                    eprintln!("receiver: connection {n}: framing: {e:?}");
                    return;
                }
            }
        }
        if !lines.is_empty() {
            let mut f = sink.lock().unwrap();
            let _ = f.write_all(&lines);
            let _ = f.flush();
        }
        if mode == Mode::Slow {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    eprintln!("receiver: connection {n} ended: {msgs} message(s)");
}
