//! The mock agent: a thread of this test serving the case's Unix socket in
//! the case's directory, with nn-proto's frames. It answers each frame it
//! reads with the next reply of its script, and keeps what it read, to be
//! written in the golden file: each request decoded, its time, nonce and
//! signatures checked and then named (`norm.rs`). No agent, no root.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nn_proto::admin_protocol::{decode_frame, encode_frame, AdminMessage, MAX_FRAME_BODY};
use nn_proto::admin_signed_payload::SignedPayload;

use crate::fixtures;

/// The socket's name in the case's directory (`--socket admin.sock`).
pub const SOCKET: &str = "admin.sock";

/// The nonce of every challenge the mock issues.
pub const NONCE: [u8; 32] = [0x4e; 32];

/// How the mock answers one frame.
#[derive(Clone, Debug)]
pub enum Reply {
    /// A frame: its label in the golden file, and the message.
    Send(String, Box<AdminMessage>),
    /// The connection closed, nothing written.
    Close,
    /// A frame whose body is not a message.
    Garbage,
    /// A length header over the frame limit, then the connection closed.
    Oversize,
    /// A frame cut after 10 of its 64 bytes, then the connection closed.
    Truncated,
}

#[derive(Clone, Debug)]
pub enum Script {
    /// The replies to the first frames of the first connection, in order;
    /// a frame after them is answered by closing the connection.
    Replies(Vec<Reply>),
    /// A socket file nobody listens on (`ECONNREFUSED`).
    Refused,
}

impl Reply {
    pub fn send(label: impl Into<String>, msg: AdminMessage) -> Self {
        Reply::Send(label.into(), Box::new(msg))
    }
}

impl Script {
    /// The signed verbs: a challenge, then `reply` to the request.
    pub fn signed(reply: Reply) -> Self {
        Script::Replies(vec![challenge(), reply])
    }

    /// The unsigned verbs (`status`, `net status` without a key).
    pub fn unsigned(reply: Reply) -> Self {
        Script::Replies(vec![reply])
    }
}

pub fn challenge() -> Reply {
    Reply::send(
        "Challenge(<challenge>)",
        AdminMessage::Challenge(nn_proto::admin_protocol::Challenge { nonce: NONCE }),
    )
}

pub struct Running {
    stop: Arc<AtomicBool>,
    handle: JoinHandle<Vec<String>>,
}

impl Running {
    /// Stop serving (nn-admin has exited) and give what the mock saw.
    pub fn finish(self) -> Vec<String> {
        self.stop.store(true, Ordering::SeqCst);
        self.handle.join().expect("the mock agent's thread")
    }
}

pub fn start(path: &Path, script: Script) -> Running {
    let stop = Arc::new(AtomicBool::new(false));
    let listener = UnixListener::bind(path)
        .unwrap_or_else(|e| panic!("binding the mock agent at {}: {e}", path.display()));
    let replies = match script {
        Script::Refused => {
            drop(listener);
            let handle =
                std::thread::spawn(|| vec!["(a socket file nobody listens on)".to_string()]);
            return Running { stop, handle };
        }
        Script::Replies(r) => r,
    };
    listener.set_nonblocking(true).unwrap();
    let flag = stop.clone();
    let handle = std::thread::spawn(move || {
        let mut log = Vec::new();
        let mut n = 0;
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    n += 1;
                    log.push(format!("connection {n}"));
                    // Only the first connection follows the script.
                    let script: &[Reply] = if n == 1 { &replies } else { &[] };
                    serve(stream, script, &mut log);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if flag.load(Ordering::SeqCst) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => {
                    log.push(format!("accept: {e}"));
                    break;
                }
            }
        }
        log
    });
    Running { stop, handle }
}

fn serve(mut stream: UnixStream, script: &[Reply], log: &mut Vec<String>) {
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let mut i = 0;
    loop {
        let mut header = [0u8; 4];
        match read_full(&mut stream, &mut header) {
            Ok(0) => {
                log.push("> (closed)".to_string());
                return;
            }
            Ok(n) if n < 4 => {
                log.push(format!("> (closed after {n} byte(s) of a header)"));
                return;
            }
            Ok(_) => {}
            Err(e) => {
                log.push(format!("> (read error: {e})"));
                return;
            }
        }
        let len = u32::from_be_bytes(header) as usize;
        if len > MAX_FRAME_BODY {
            log.push(format!("> (a header of {len} bytes, over the limit)"));
            return;
        }
        let mut body = vec![0u8; len];
        match read_full(&mut stream, &mut body) {
            Ok(n) if n == len => {}
            Ok(n) => {
                log.push(format!("> (closed after {n} of {len} bytes)"));
                return;
            }
            Err(e) => {
                log.push(format!("> (read error: {e})"));
                return;
            }
        }
        let mut frame = header.to_vec();
        frame.extend_from_slice(&body);
        match decode_frame(&frame) {
            Ok(Some((msg, _))) => log.push(format!("> {}", request(&msg))),
            Ok(None) => log.push("> (an incomplete frame)".to_string()),
            Err(e) => log.push(format!("> (undecodable: {e})")),
        }
        let Some(reply) = script.get(i) else {
            log.push("< (closed: no reply scripted)".to_string());
            return;
        };
        i += 1;
        match reply {
            Reply::Send(label, msg) => {
                let bytes = encode_frame(msg).expect("encode the mock's reply");
                let _ = stream.write_all(&bytes);
                log.push(format!("< {label}"));
            }
            Reply::Close => {
                log.push("< (closed without a reply)".to_string());
                return;
            }
            Reply::Garbage => {
                let mut b = 8u32.to_be_bytes().to_vec();
                b.extend_from_slice(&[0xff; 8]);
                let _ = stream.write_all(&b);
                log.push("< (a frame of 8 bytes 0xff: no message)".to_string());
            }
            Reply::Oversize => {
                let _ = stream.write_all(&((MAX_FRAME_BODY as u32) + 1).to_be_bytes());
                log.push(format!(
                    "< (a header of {} bytes, then closed)",
                    MAX_FRAME_BODY + 1
                ));
                return;
            }
            Reply::Truncated => {
                let mut b = 64u32.to_be_bytes().to_vec();
                b.extend_from_slice(&[0u8; 10]);
                let _ = stream.write_all(&b);
                log.push("< (a header of 64 bytes, 10 sent, then closed)".to_string());
                return;
            }
        }
    }
}

/// Read until `buf` is full or the peer closes; the bytes read.
fn read_full(stream: &mut UnixStream, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut got = 0;
    while got < buf.len() {
        match stream.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(got)
}

/// A request as the golden file shows it: the message as JSON, its signed
/// payload's time, nonce and signatures checked and named.
fn request(msg: &AdminMessage) -> String {
    let mut v = serde_json::to_value(msg).expect("a message as JSON");
    normalise(&mut v);
    serde_json::to_string(&v).unwrap()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn normalise(v: &mut serde_json::Value) {
    use serde_json::Value;
    match v {
        Value::Object(map) => {
            if let (Some(p), Some(Value::Array(sigs))) = (map.get("payload"), map.get("signatures"))
            {
                if let Ok(payload) = serde_json::from_value::<SignedPayload>(p.clone()) {
                    let labels: Vec<Value> = sigs
                        .iter()
                        .map(|s| {
                            let sig: Option<[u8; 64]> = s
                                .get("signature")
                                .and_then(|x| serde_json::from_value::<Vec<u8>>(x.clone()).ok())
                                .and_then(|b| b.try_into().ok());
                            Value::String(match sig {
                                Some(sig) => fixtures::signer_of(&payload, &sig),
                                None => "<sig: not 64 bytes>".to_string(),
                            })
                        })
                        .collect();
                    map.insert("signatures".to_string(), Value::Array(labels));
                    let p = map.get_mut("payload").unwrap();
                    let ts = payload.ts;
                    let t = now();
                    p["ts"] = if ts + 300 >= t && ts <= t + 300 {
                        "<now>".into()
                    } else {
                        format!("<ts {ts}: not within 5 minutes of the mock's clock>").into()
                    };
                    p["nonce"] = if payload.nonce == NONCE {
                        "<challenge>".into()
                    } else {
                        format!("<nonce {}: not the challenge>", hex::encode(payload.nonce)).into()
                    };
                }
            }
            for (_, x) in map.iter_mut() {
                normalise(x);
            }
        }
        Value::Array(items) => {
            items.iter_mut().for_each(normalise);
            crate::norm::hex_arrays(v);
        }
        _ => {}
    }
}
