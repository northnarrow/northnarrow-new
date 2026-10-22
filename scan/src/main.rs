//! `northnarrow-scan` (lab PR 223, EXPERIMENTAL): spawned by the agent as
//! its own unprivileged user with the channel on descriptor 3. It reads its
//! configuration from the sealed memfd of the first message, confines
//! itself (seccomp: no file, no network, no process), says it is ready,
//! then answers one scan per packet until the agent closes the channel.

use std::os::fd::{AsRawFd, RawFd};
use std::process::ExitCode;

use nn_proto::execq::{
    decode, decode_config, encode, FromScanner, ToScanner, MAX_CONFIG_BYTES, MAX_PACKET,
    PROTOCOL_VERSION,
};
use northnarrow_scan::engine::Engine;
use northnarrow_scan::ipc::{self, FdFile};
use northnarrow_scan::{harden, seccomp, SOCKET_FD};

fn fail(why: impl std::fmt::Display) -> ExitCode {
    eprintln!("northnarrow-scan: {why}");
    ExitCode::from(2)
}

fn reply(sock: RawFd, msg: &FromScanner) -> Result<(), String> {
    let bytes = encode(msg)?;
    ipc::send(sock, &bytes, None).map_err(|e| format!("send: {e}"))
}

fn main() -> ExitCode {
    let mut sock: RawFd = SOCKET_FD;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--version" => {
                println!("northnarrow-scan {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            "--fd" => match args.next().and_then(|v| v.parse().ok()) {
                Some(fd) => sock = fd,
                None => return fail("--fd needs a descriptor number"),
            },
            other => return fail(format!("unknown argument `{other}`")),
        }
    }
    if let Err(e) = harden::harden(sock) {
        return fail(e);
    }
    let mut buf = vec![0u8; MAX_PACKET];

    // 1. The configuration, from the memfd of the first message.
    let pkt = match ipc::recv(sock, &mut buf, false) {
        Ok(p) if p.len > 0 => p,
        Ok(_) => return fail("the agent closed the channel before configuring"),
        Err(e) => return fail(format!("recv: {e}")),
    };
    let config_len = match decode::<ToScanner>(&buf[..pkt.len]) {
        Ok(ToScanner::Configure {
            version,
            config_len,
        }) if version == PROTOCOL_VERSION => config_len,
        Ok(ToScanner::Configure { version, .. }) => {
            return fail(format!(
                "protocol {version}, this scanner speaks {PROTOCOL_VERSION}"
            ))
        }
        Ok(_) => return fail("the first message must configure"),
        Err(e) => return fail(format!("decode: {e}")),
    };
    let Some(memfd) = pkt.fd else {
        return fail("configuration without its memfd");
    };
    let cfg = match ipc::read_all_at(memfd.as_raw_fd(), config_len, MAX_CONFIG_BYTES)
        .map_err(|e| e.to_string())
        .and_then(|b| decode_config(&b))
    {
        Ok(c) => c,
        Err(e) => return fail(format!("configuration: {e}")),
    };
    drop(memfd);
    let engine = Engine::new(&cfg);
    drop(cfg);
    // The prefix buffer, a 1 MiB chunk, the lists and the allocator's slack.
    if let Err(e) = harden::limit_memory(engine.max_read().saturating_mul(2) + (512 << 20)) {
        return fail(e);
    }

    // SAFETY: getuid has no preconditions (and is not allowed past here).
    let uid = unsafe { libc::getuid() };
    // 2. Confined from here on.
    if let Err(e) = seccomp::install() {
        return fail(format!("seccomp: {e}"));
    }
    if let Err(e) = reply(sock, &FromScanner::Ready(engine.hello(uid, true))) {
        return fail(e);
    }

    // 3. One scan per packet.
    loop {
        let pkt = match ipc::recv(sock, &mut buf, false) {
            Ok(p) if p.len == 0 => return ExitCode::SUCCESS,
            Ok(p) => p,
            Err(e) => return fail(format!("recv: {e}")),
        };
        let answer = match decode::<ToScanner>(&buf[..pkt.len]) {
            Ok(ToScanner::Scan(req)) => match &pkt.fd {
                None => FromScanner::Refused {
                    id: req.id,
                    reason: "no descriptor".into(),
                },
                Some(fd) => {
                    let file = FdFile(fd);
                    match file.stat() {
                        Ok((mode, _)) if mode & libc::S_IFMT == libc::S_IFREG => {
                            FromScanner::Result(engine.scan(&file, &req))
                        }
                        Ok(_) => FromScanner::Refused {
                            id: req.id,
                            reason: "not a regular file".into(),
                        },
                        Err(e) => FromScanner::Refused {
                            id: req.id,
                            reason: format!("fstat: {e}"),
                        },
                    }
                }
            },
            Ok(ToScanner::Configure { .. }) => FromScanner::Refused {
                id: 0,
                reason: "already configured".into(),
            },
            Err(e) => return fail(format!("decode: {e}")),
        };
        drop(pkt);
        if let Err(e) = reply(sock, &answer) {
            return fail(e);
        }
    }
}
