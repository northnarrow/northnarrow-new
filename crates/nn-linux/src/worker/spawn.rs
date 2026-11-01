//! Starting a worker (R14a, plan §3.5): the agent's own binary, from the
//! descriptor the core opened at boot ([`SelfImage`]: `/proc/self/fd/N`,
//! never a path that could name another file by then), as `northnarrow-agent
//! --worker <kind> --ipc-fd 3`, as the `northnarrow-worker` account.
//!
//! Between `fork` and `exec` the child does async-signal-safe system calls
//! only (`pre_exec`): its channel on descriptor 3, `setgroups(0)`,
//! `setresgid`, `setresuid` (raw system calls: the child has one thread),
//! `PR_SET_NO_NEW_PRIVS`, `PR_SET_PDEATHSIG` (after the uid change, which
//! clears it) and a check that the core still lives, then every other
//! descriptor close-on-exec (`close_range(4, ~0, CLOSE_RANGE_CLOEXEC)`: the
//! image's descriptor is resolved by `execve` before the close happens).
//! The environment is empty, the directory `/`, stdin and stdout
//! `/dev/null`; stderr is the agent's (its journal).

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};

use nn_proto::ipc::WorkerKind;

use super::{transport, SelfImage, WorkerAccount};

/// The descriptor a worker finds its channel on.
pub const IPC_FD: i32 = 3;

/// `close_range(2)`'s flag: mark close-on-exec instead of closing (5.11).
const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;

/// A started worker: the child and the core's end of its channel.
#[derive(Debug)]
pub struct Spawned {
    pub child: Child,
    pub sock: OwnedFd,
}

/// The worker's argument vector after `argv[0]`.
pub fn worker_args(kind: WorkerKind) -> [String; 4] {
    [
        "--worker".to_string(),
        kind.name().to_string(),
        "--ipc-fd".to_string(),
        IPC_FD.to_string(),
    ]
}

/// Start a `kind` worker from `image` as `account`; `extra` arguments
/// follow (the lab harness's).
pub fn spawn(
    image: &SelfImage,
    kind: WorkerKind,
    account: &WorkerAccount,
    extra: &[String],
) -> io::Result<Spawned> {
    if account.uid == 0 || account.gid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "a worker never runs as root or group 0",
        ));
    }
    let (ours, theirs) = transport::socketpair()?;
    let raw = theirs.as_raw_fd();
    let (uid, gid) = (account.uid, account.gid);
    // SAFETY: getpid has no preconditions.
    let core = unsafe { libc::getpid() };
    let mut cmd = Command::new(image.exec_path());
    cmd.arg0("northnarrow-agent")
        .args(worker_args(kind))
        .args(extra)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    // SAFETY: async-signal-safe system calls only, in the child between
    // fork and exec; no allocation, no lock.
    unsafe {
        cmd.pre_exec(move || {
            let check = |rc: libc::c_long| -> io::Result<()> {
                if rc < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            };
            let rc = if raw == IPC_FD {
                libc::fcntl(IPC_FD, libc::F_SETFD, 0)
            } else {
                libc::dup2(raw, IPC_FD)
            };
            check(rc as libc::c_long)?;
            check(libc::syscall(
                libc::SYS_setgroups,
                0usize,
                std::ptr::null::<libc::gid_t>(),
            ))?;
            check(libc::syscall(libc::SYS_setresgid, gid, gid, gid))?;
            check(libc::syscall(libc::SYS_setresuid, uid, uid, uid))?;
            check(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) as libc::c_long)?;
            // after the uid change, which clears it: die with the core
            check(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) as libc::c_long)?;
            if libc::getppid() != core {
                // the core died before the death signal was armed
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            // everything above the channel close-on-exec (the image's
            // descriptor is resolved by execve before that); a kernel
            // without the flag leaves it to the worker's own close
            libc::syscall(
                libc::SYS_close_range,
                (IPC_FD + 1) as libc::c_uint,
                libc::c_uint::MAX,
                CLOSE_RANGE_CLOEXEC,
            );
            Ok(())
        });
    }
    let child = cmd.spawn()?;
    drop(theirs);
    Ok(Spawned { child, sock: ours })
}
