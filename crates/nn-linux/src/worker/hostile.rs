//! The compromised worker (R14a; `debug-trigger` builds only — the lab's
//! harness, `agent/tests/privileged_worker_harness.rs`,
//! `docs/architecture/PROCESS_MODEL.md` §5).
//!
//! `--worker parse --ipc-fd 3 --hostile <attack>` behaves as a worker whose
//! parser an input took over: it was started by the core's own spawn path
//! (the account, `no_new_privs`, the descriptors), it enters the real
//! sandbox, then it does `<attack>` instead of its work. Two families:
//!
//! - a system call it should not make — read a key, open or create a file,
//!   connect out, connect to an abstract socket, signal or trace a
//!   process, execute, fork, `bpf`, `setuid`, executable memory. Under the
//!   sandbox each one is killed by the seccomp filter (`SIGSYS`). With the
//!   prefix `noseccomp+` (this harness only) the worker enters everything
//!   but the filter, so the layers beneath it answer: the account (DAC),
//!   Landlock at the kernel's ABI, `RLIMIT_NPROC`, the capability sets, the
//!   BPF LSM hooks. It exits [`DENIED`] when the call failed with
//!   `EACCES`/`EPERM`, [`FAILED`] on another error, [`SUCCEEDED`] when it
//!   went through;
//! - a protocol attack, after a genuine hello, on the core's first request:
//!   a malformed packet, an oversized one, a descriptor sent along, an
//!   answer to an id never asked, a second hello, a flood of answers, a
//!   lie in a result (a name with a newline), a hello below its sandbox.
//!   The core must refuse each one and kill the worker.

use std::os::fd::RawFd;

use nn_proto::ipc::{
    decode, encode, Answer, FromWorker, QnameOut, Request, Response, ToWorker, WorkerHello,
    IPC_VERSION, MAX_FRAME,
};

use super::serve::{Args, EXIT_SANDBOX, EXIT_USAGE};
use super::transport::{self, Recv};
use crate::sandbox;

/// The attack's call went through.
pub const SUCCEEDED: i32 = 40;
/// It failed with `EACCES` or `EPERM` (or `EAGAIN` for a fork past
/// `RLIMIT_NPROC`): a layer refused it.
pub const DENIED: i32 = 41;
/// It failed with another error (the errno on stderr).
pub const FAILED: i32 = 42;

/// The system-call attacks and the protocol attacks, by name.
pub const SYSCALL_ATTACKS: &[&str] = &[
    "read",
    "write",
    "connect",
    "connect-abstract",
    "kill",
    "ptrace",
    "exec",
    "fork",
    "bpf",
    "setuid",
    "mmap-exec",
];
pub const PROTOCOL_ATTACKS: &[&str] = &[
    "malformed",
    "oversized",
    "fd-pass",
    "unknown-id",
    "second-hello",
    "flood",
    "lie",
    "weak-hello",
];

/// Run `attack` (`[noseccomp+]<name>[:<argument>]`); the exit status.
pub fn run(a: &Args, attack: &str) -> i32 {
    let (no_seccomp, attack) = match attack.strip_prefix("noseccomp+") {
        Some(rest) => (true, rest),
        None => (false, attack),
    };
    let (name, arg) = attack.split_once(':').unwrap_or((attack, ""));
    let profile = sandbox::Profile::parse(a.ipc_fd);
    let level = match if no_seccomp {
        sandbox::enter_without_seccomp(&profile)
    } else {
        sandbox::enter(&profile)
    } {
        Ok(l) => l,
        Err(e) => {
            eprintln!("hostile worker: sandbox not entered: {e}");
            return EXIT_SANDBOX;
        }
    };
    if SYSCALL_ATTACKS.contains(&name) {
        let (code, what) = match syscall_attack(name, arg) {
            Ok(()) => (SUCCEEDED, "went through".to_string()),
            Err(e) => (
                if matches!(e, libc::EACCES | libc::EPERM | libc::EAGAIN) {
                    DENIED
                } else {
                    FAILED
                },
                std::io::Error::from_raw_os_error(e).to_string(),
            ),
        };
        eprintln!("hostile worker {name}({arg}): exit {code}: {what}");
        return code;
    }
    if PROTOCOL_ATTACKS.contains(&name) {
        return protocol_attack(a.ipc_fd, name, level);
    }
    eprintln!("hostile worker: no attack `{name}`");
    EXIT_USAGE
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn cstr(s: &str) -> Result<std::ffi::CString, i32> {
    std::ffi::CString::new(s).map_err(|_| libc::EINVAL)
}

/// One forbidden call: `Ok` when it went through, the errno otherwise.
fn syscall_attack(name: &str, arg: &str) -> Result<(), i32> {
    // SAFETY (every block below): plain system calls with valid arguments
    // the worker owns; a success is the finding, not a hazard to the core
    // (whose own safety is what the harness checks).
    unsafe {
        let ok = |rc: libc::c_long| if rc < 0 { Err(errno()) } else { Ok(()) };
        match name {
            "read" => {
                let p = cstr(arg)?;
                ok(libc::syscall(
                    libc::SYS_openat,
                    libc::AT_FDCWD,
                    p.as_ptr(),
                    libc::O_RDONLY,
                ))
            }
            "write" => {
                let p = cstr(arg)?;
                ok(libc::syscall(
                    libc::SYS_openat,
                    libc::AT_FDCWD,
                    p.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
                    0o600,
                ))
            }
            "connect" => {
                let addr: std::net::SocketAddrV4 = arg.parse().map_err(|_| libc::EINVAL)?;
                let fd = libc::syscall(libc::SYS_socket, libc::AF_INET, libc::SOCK_STREAM, 0);
                ok(fd)?;
                let sa = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: addr.port().to_be(),
                    sin_addr: libc::in_addr {
                        s_addr: u32::from(*addr.ip()).to_be(),
                    },
                    sin_zero: [0; 8],
                };
                ok(libc::syscall(
                    libc::SYS_connect,
                    fd,
                    &sa as *const libc::sockaddr_in,
                    std::mem::size_of::<libc::sockaddr_in>(),
                ))
            }
            "connect-abstract" => {
                let fd = libc::syscall(libc::SYS_socket, libc::AF_UNIX, libc::SOCK_STREAM, 0);
                ok(fd)?;
                let mut sa: libc::sockaddr_un = std::mem::zeroed();
                sa.sun_family = libc::AF_UNIX as libc::sa_family_t;
                let bytes = arg.as_bytes();
                let n = bytes.len().min(sa.sun_path.len() - 1);
                for (i, b) in bytes[..n].iter().enumerate() {
                    sa.sun_path[i + 1] = *b as libc::c_char;
                }
                let len = std::mem::size_of::<libc::sa_family_t>() + 1 + n;
                ok(libc::syscall(
                    libc::SYS_connect,
                    fd,
                    &sa as *const libc::sockaddr_un,
                    len,
                ))
            }
            "kill" => {
                let pid: i32 = if arg.is_empty() {
                    libc::getppid()
                } else {
                    arg.parse().map_err(|_| libc::EINVAL)?
                };
                // SIGCONT: harmless if it lands, and allowed by DAC within
                // a session — what refuses it is a policy layer
                ok(libc::syscall(libc::SYS_kill, pid, libc::SIGCONT))
            }
            "ptrace" => {
                let pid: i32 = if arg.is_empty() {
                    libc::getppid()
                } else {
                    arg.parse().map_err(|_| libc::EINVAL)?
                };
                let rc = libc::syscall(libc::SYS_ptrace, libc::PTRACE_ATTACH, pid, 0, 0);
                if rc == 0 {
                    // let go at once (a stopped core would hang the harness)
                    libc::syscall(libc::SYS_ptrace, libc::PTRACE_DETACH, pid, 0, 0);
                }
                ok(rc)
            }
            "exec" => {
                // a shell that exits with SUCCEEDED: the exec went through
                let sh = cstr(if arg.is_empty() { "/bin/sh" } else { arg })?;
                let c = cstr("-c")?;
                let script = cstr(&format!("exit {SUCCEEDED}"))?;
                let argv = [sh.as_ptr(), c.as_ptr(), script.as_ptr(), std::ptr::null()];
                let envp = [std::ptr::null::<libc::c_char>()];
                ok(libc::syscall(
                    libc::SYS_execve,
                    sh.as_ptr(),
                    argv.as_ptr(),
                    envp.as_ptr(),
                ))
            }
            "fork" => {
                let rc = libc::fork();
                if rc == 0 {
                    libc::_exit(0);
                }
                ok(rc as libc::c_long)
            }
            "bpf" => {
                // BPF_MAP_GET_FD_BY_ID for map id 1
                let mut attr = [0u32; 32];
                attr[0] = 1;
                ok(libc::syscall(
                    libc::SYS_bpf,
                    14 as libc::c_long,
                    attr.as_mut_ptr(),
                    std::mem::size_of_val(&attr),
                ))
            }
            "setuid" => ok(libc::syscall(libc::SYS_setuid, 0)),
            "mmap-exec" => {
                let m = libc::syscall(
                    libc::SYS_mmap,
                    0,
                    4096,
                    libc::PROT_READ | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                if m == -1 {
                    Err(errno())
                } else {
                    Ok(())
                }
            }
            _ => Err(libc::EINVAL),
        }
    }
}

fn send(fd: RawFd, m: &FromWorker) {
    if let Ok(b) = encode(m) {
        let _ = transport::send(fd, &b);
    }
}

fn raw_send(fd: RawFd, bytes: &[u8]) {
    let iov = libc::iovec {
        iov_base: bytes.as_ptr() as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    // SAFETY: a zeroed msghdr with one live iovec, on the worker's channel.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &iov as *const _ as *mut _;
        msg.msg_iovlen = 1;
        libc::sendmsg(fd, &msg, libc::MSG_NOSIGNAL);
    }
}

/// A genuine hello, then `name` on the core's first request; exits when
/// the core closes the channel (it should, having killed us first).
fn protocol_attack(fd: RawFd, name: &str, level: nn_proto::ipc::SandboxLevel) -> i32 {
    // SAFETY: getpid has no preconditions.
    let pid = unsafe { libc::getpid() } as u32;
    let mut hello = WorkerHello {
        version: IPC_VERSION,
        kind: nn_proto::ipc::WorkerKind::Parse,
        pid,
        sandbox: level,
    };
    if name == "weak-hello" {
        hello.sandbox.seccomp = false;
        hello.sandbox.uid = 0;
    }
    send(fd, &FromWorker::Hello(hello.clone()));
    let mut buf = vec![0u8; MAX_FRAME];
    let n = match transport::recv(fd, &mut buf, false) {
        Ok(Recv::Packet(n)) => n,
        _ => return 0,
    };
    let Ok(msg) = decode::<ToWorker>(&buf[..n]) else {
        return 0;
    };
    let answer = super::serve::answer(&msg.req);
    match name {
        "malformed" => raw_send(fd, &[0xde, 0xad, 0xbe, 0xef, 0xff, 0xff]),
        "oversized" => raw_send(fd, &vec![0x41u8; MAX_FRAME + 4096]),
        "fd-pass" => send_with_fd(fd),
        "unknown-id" => send(
            fd,
            &FromWorker::Response(Response {
                id: msg.id.wrapping_add(1000),
                answer,
            }),
        ),
        "second-hello" => send(fd, &FromWorker::Hello(hello)),
        "flood" => {
            for _ in 0..100_000 {
                // until the core kills us or the socket fills
                let b = encode(&FromWorker::Response(Response {
                    id: msg.id,
                    answer: answer.clone(),
                }));
                let Ok(b) = b else { break };
                if transport::send(fd, &b).is_err() {
                    break;
                }
            }
        }
        "lie" => {
            let lie = match &msg.req {
                Request::DnsNames(n) => Answer::DnsNames(
                    n.iter()
                        .map(|_| QnameOut {
                            name: "evil.example\n2026-11-01 forged log line".into(),
                            end: None,
                        })
                        .collect(),
                ),
                _ => Answer::DnsNames(vec![]),
            };
            send(
                fd,
                &FromWorker::Response(Response {
                    id: msg.id,
                    answer: lie,
                }),
            );
        }
        _ => {}
    }
    // wait for the core to end us
    loop {
        match transport::recv(fd, &mut buf, false) {
            Ok(Recv::Closed) | Err(_) => return 0,
            _ => {}
        }
    }
}

fn send_with_fd(fd: RawFd) {
    let payload = encode(&FromWorker::Response(Response {
        id: 1,
        answer: Answer::Pong,
    }))
    .unwrap_or_default();
    let iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };
    let mut cbuf = [0u64; 8];
    // SAFETY: a zeroed msghdr, one iovec, a control buffer for one
    // descriptor (our own channel's) written within it.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &iov as *const _ as *mut _;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr().cast();
        msg.msg_controllen = libc::CMSG_SPACE(4) as _;
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(4) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(c) as *mut RawFd, fd);
        libc::sendmsg(fd, &msg, libc::MSG_NOSIGNAL);
    }
}
