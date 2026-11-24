//! Starting a worker (R14a, plan §3.5): the agent's own binary, from the
//! descriptor the core opened at boot ([`SelfImage`], executed by its
//! descriptor — `execveat(fd, "", …, AT_EMPTY_PATH)`, lot 353: never a path
//! that could name another file by then, nor one walked through the `/proc`
//! mounted now), as `northnarrow-agent
//! --worker <kind> --ipc-fd 3`, as the `northnarrow-worker` account.
//!
//! Between `fork` and `exec` the child does async-signal-safe system calls
//! only (`pre_exec`): its channel on descriptor 3, `setgroups(0)`,
//! `setresgid`, `setresuid` (raw system calls: the child has one thread),
//! `PR_SET_NO_NEW_PRIVS`, `PR_SET_PDEATHSIG` (after the uid change, which
//! clears it) and a check that the core still lives, then every other
//! descriptor close-on-exec (`close_range(4, ~0, CLOSE_RANGE_CLOEXEC)`: the
//! image's descriptor is resolved by `execveat` before the close happens).
//! The environment is empty, the directory `/`, stdin and stdout
//! `/dev/null`. Review of #480: stderr is a pipe the supervisor reads
//! (F4: a worker writes no line of the agent's journal itself); before the
//! uid change the child sets its own `oom_score_adj` to 1000 and its nice
//! to 10 (F12: under memory pressure a worker dies before the core, and it
//! never takes the CPU from it); a failure of either fails the start.

// The raw `setgroups`/`setresgid`/`setresuid` numbers below are the
// 32-bit-id calls on these two architectures only (review of #480, INFO):
// another one must be checked before it builds.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("worker::spawn's raw id system calls are checked for x86_64 and aarch64 only");

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};

use nn_proto::ipc::WorkerKind;

use super::{SelfImage, WorkerAccount, transport};

/// The descriptor a worker finds its channel on.
pub const IPC_FD: i32 = 3;

/// `close_range(2)`'s flag: mark close-on-exec instead of closing (5.11).
const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;

/// A started worker: the child, the core's end of its channel, and the
/// read end of its stderr (non-blocking; `None` for the tests' workers).
#[derive(Debug)]
pub struct Spawned {
    pub child: Child,
    pub sock: OwnedFd,
    pub stderr: Option<OwnedFd>,
}

/// The worker's `oom_score_adj`: the first the kernel's OOM killer takes.
pub const WORKER_OOM_SCORE_ADJ: &[u8] = b"1000";
/// The worker's nice value.
pub const WORKER_NICE: libc::c_int = 10;

/// A pipe for the worker's stderr: (read end, non-blocking and
/// close-on-exec; write end, close-on-exec — `Command` puts it on 2).
fn stderr_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: a valid out-array of two ints.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the kernel just returned these two descriptors to us.
    let (r, w) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    // SAFETY: fcntl on our own descriptor.
    unsafe {
        let fl = libc::fcntl(r.as_raw_fd(), libc::F_GETFL);
        libc::fcntl(r.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK);
    }
    Ok((r, w))
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

/// Review of #480 (F12), in the child before `exec`: its own
/// `oom_score_adj` [`WORKER_OOM_SCORE_ADJ`] and nice [`WORKER_NICE`] —
/// raising either needs no privilege. Async-signal-safe: `open`, `write`,
/// `close`, `setpriority`, no allocation.
fn yield_first() -> io::Result<()> {
    // SAFETY: a static NUL-terminated path; a local descriptor written
    // from a static buffer and closed.
    unsafe {
        // lot 353: beneath the `/proc` root the core's start anchored (no
        // mount laid over `/proc` since is walked; no allocation)
        let anchored = match antitamper_bpf::kernel_roots::proc_root_fd().filter(|fd| *fd > IPC_FD)
        {
            Some(proc) => libc::openat(
                proc,
                c"self/oom_score_adj".as_ptr(),
                libc::O_WRONLY | libc::O_CLOEXEC,
            ),
            None => -1,
        };
        let fd = if anchored >= 0 {
            anchored
        } else {
            libc::open(
                c"/proc/self/oom_score_adj".as_ptr(),
                libc::O_WRONLY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = libc::write(
            fd,
            WORKER_OOM_SCORE_ADJ.as_ptr().cast(),
            WORKER_OOM_SCORE_ADJ.len(),
        );
        let err = io::Error::last_os_error();
        libc::close(fd);
        if n < 0 {
            return Err(err);
        }
        if libc::setpriority(libc::PRIO_PROCESS, 0, WORKER_NICE) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Lot 353 (re-check 2 of #563): an exec of a descriptor, its argv and
/// its empty environment made before the fork — the child's `execveat`
/// allocates nothing.
struct FdExec {
    fd: libc::c_int,
    _args: Vec<std::ffi::CString>,
    argv: Vec<*const libc::c_char>,
    envp: [*const libc::c_char; 1],
}

// SAFETY: the pointers are into `_args`, owned and never changed while the
// value lives; the child reads them only.
unsafe impl Send for FdExec {}
// SAFETY: as above, read only.
unsafe impl Sync for FdExec {}

impl FdExec {
    fn new(fd: libc::c_int, args: impl Iterator<Item = String>) -> io::Result<Self> {
        let args: Vec<std::ffi::CString> = args
            .map(|a| {
                std::ffi::CString::new(a).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
            })
            .collect::<io::Result<_>>()?;
        let argv = args
            .iter()
            .map(|a| a.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();
        Ok(Self {
            fd,
            _args: args,
            argv,
            envp: [std::ptr::null()],
        })
    }

    /// `execveat(fd, "", argv, envp, AT_EMPTY_PATH)`: its error, when it
    /// returns. Async-signal-safe, no allocation.
    fn run(&self) -> io::Error {
        // SAFETY: the descriptor is live in the child (close-on-exec only),
        // the arrays are NUL-terminated and outlive the call.
        unsafe {
            libc::syscall(
                libc::SYS_execveat,
                self.fd,
                c"".as_ptr(),
                self.argv.as_ptr(),
                self.envp.as_ptr(),
                libc::AT_EMPTY_PATH,
            );
        }
        io::Error::last_os_error()
    }
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
    let (err_read, err_write) = stderr_pipe()?;
    let raw = theirs.as_raw_fd();
    let (uid, gid) = (account.uid, account.gid);
    // SAFETY: getpid has no preconditions.
    let core = unsafe { libc::getpid() };
    // Lot 353 (re-check 2 of #563): the child executes the image's
    // descriptor (`execveat(fd, "", …, AT_EMPTY_PATH)`, the last step of its
    // `pre_exec`): no path is walked — `Command::new("/proc/self/fd/N")`
    // walked the `/proc` mounted now in the child, and a FUSE over it held
    // the exec and the supervisor waiting for it. The program named here is
    // never executed by path; argv and the (empty) environment are made
    // before the fork.
    let exec = FdExec::new(
        image.raw_fd(),
        std::iter::once("northnarrow-agent".to_string())
            .chain(worker_args(kind))
            .chain(extra.iter().cloned()),
    )?;
    let mut cmd = Command::new("northnarrow-agent");
    cmd.arg0("northnarrow-agent")
        .args(worker_args(kind))
        .args(extra)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(err_write));
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
            // F12, as root still: the OOM killer's first choice, and a low
            // priority (a failure fails the start)
            yield_first()?;
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
            // the image itself, by its descriptor (returns only on failure)
            Err(exec.run())
        });
    }
    let child = cmd.spawn()?;
    drop(theirs);
    Ok(Spawned {
        child,
        sock: ours,
        stderr: Some(err_read),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review of #480 (F12; the review's mutation N27): the child the core
    /// starts is the OOM killer's first choice and the scheduler's last —
    /// without a privilege, so this test's own child shows it.
    #[test]
    fn the_child_yields_first() {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("cat /proc/self/oom_score_adj; cut -d' ' -f19 /proc/self/stat");
        // SAFETY: yield_first makes async-signal-safe calls only.
        unsafe { cmd.pre_exec(yield_first) };
        let out = cmd.output().unwrap();
        assert!(out.status.success(), "{out:?}");
        let text = String::from_utf8_lossy(&out.stdout);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines, ["1000", "10"], "{text}");
    }
}
