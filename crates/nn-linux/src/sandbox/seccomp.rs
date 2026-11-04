//! The workers' seccomp allowlists (R14a, plan §3.1), compiled to classic
//! BPF by `seccompiler` (pure Rust; no libseccomp).
//!
//! The `parse` worker keeps (plan §3.1's list, narrowed by its arguments):
//!
//! - its channel: `recvfrom` and `sendto` on the IPC descriptor only, with
//!   no address and the transport's own flags (review of #480, F8: no
//!   `sendmsg`, so no `SCM_RIGHTS` from the worker — the UNIX sockets'
//!   garbage collector is not its to reach);
//! - `write` to stderr only (its diagnostics reach the agent's journal);
//! - memory: `brk`, `mmap` and `mprotect` without `PROT_EXEC` (so no
//!   writable mapping made executable later either), `munmap`, `mremap`,
//!   `madvise`; `futex`; `close`;
//! - `clock_gettime`, `getrandom` (std's hash seeds);
//! - signal returns and masks (`rt_sigreturn`, `rt_sigprocmask`,
//!   `sigaltstack`), `restart_syscall`, `sched_yield`;
//! - an abort: `getpid`, `gettid`, and `tgkill` of itself only;
//! - `exit`, `exit_group`.
//!
//! Everything else — `open*`, `socket` (TCP, UDP, a UNIX socket by path),
//! `connect`, `exec*`, `clone*`, `fork`, `unshare` (a user namespace),
//! `kill`, `tkill`, `tgkill` of another process, `rt_sigqueueinfo`,
//! `pidfd_send_signal`, `ptrace`, `bpf`, `io_uring_setup`, `keyctl`,
//! `perf_event_open`, `userfaultfd`, `prctl`, `read` of any file,
//! `pkey_mprotect`, `sendmsg`/`recvmsg`, executable memory, another
//! architecture's numbers (and x86_64's x32 numbers, which match no rule)
//! — kills the whole process (`SECCOMP_RET_KILL_PROCESS`): the core sees
//! it die by `SIGSYS`. On every lab kernel the filter is the only layer
//! for UNIX sockets by path (Landlock from ABI 9), UDP, user namespaces,
//! `io_uring`, `keyctl`, `perf_event_open` and executable memory.

use std::collections::BTreeMap;
use std::io;
use std::os::fd::RawFd;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

/// One kept system call, with the argument checks it is kept under
/// (`(index, value)`: the argument equals the value; `NoExec(index)`: the
/// argument has no `PROT_EXEC`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg {
    Eq(u8, u64),
    /// The whole 64-bit argument equals the value (a pointer that must be
    /// null).
    Eq64(u8, u64),
    NoExec(u8),
    /// Lot 276: the argument (32 bits, unsigned) is at least the value (a
    /// descriptor above the channel).
    Ge(u8, u64),
}

/// A set of kept system calls; any other kills the process.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allowlist {
    /// `(number, name, checks)`; no check: any arguments.
    pub calls: Vec<(i64, &'static str, Vec<Arg>)>,
}

impl Allowlist {
    fn keep(&mut self, nr: libc::c_long, name: &'static str, args: Vec<Arg>) {
        self.calls.push((nr, name, args));
    }

    /// The `parse` worker's list (see the module's documentation).
    pub fn parse_worker(ipc_fd: RawFd, self_pid: u32) -> Self {
        let mut a = Self::default();
        let fd = ipc_fd as u64;
        // the transport's worker side (`transport::recv_from`, `send_to`):
        // its channel, its flags, no address
        a.keep(
            libc::SYS_recvfrom,
            "recvfrom",
            vec![
                Arg::Eq(0, fd),
                Arg::Eq(3, crate::worker::transport::WORKER_RECV_FLAGS as u64),
                Arg::Eq64(4, 0),
                Arg::Eq64(5, 0),
            ],
        );
        a.keep(
            libc::SYS_sendto,
            "sendto",
            vec![
                Arg::Eq(0, fd),
                Arg::Eq(3, crate::worker::transport::WORKER_SEND_FLAGS as u64),
                Arg::Eq64(4, 0),
                Arg::Eq64(5, 0),
            ],
        );
        a.keep(libc::SYS_write, "write", vec![Arg::Eq(0, 2)]);
        a.keep(libc::SYS_mmap, "mmap", vec![Arg::NoExec(2)]);
        a.keep(libc::SYS_mprotect, "mprotect", vec![Arg::NoExec(2)]);
        a.keep(
            libc::SYS_tgkill,
            "tgkill",
            vec![Arg::Eq(0, u64::from(self_pid))],
        );
        for (nr, name) in [
            (libc::SYS_close, "close"),
            (libc::SYS_brk, "brk"),
            (libc::SYS_munmap, "munmap"),
            (libc::SYS_mremap, "mremap"),
            (libc::SYS_madvise, "madvise"),
            (libc::SYS_futex, "futex"),
            (libc::SYS_clock_gettime, "clock_gettime"),
            (libc::SYS_getrandom, "getrandom"),
            (libc::SYS_rt_sigreturn, "rt_sigreturn"),
            (libc::SYS_rt_sigprocmask, "rt_sigprocmask"),
            (libc::SYS_sigaltstack, "sigaltstack"),
            (libc::SYS_restart_syscall, "restart_syscall"),
            (libc::SYS_sched_yield, "sched_yield"),
            (libc::SYS_getpid, "getpid"),
            (libc::SYS_gettid, "gettid"),
            (libc::SYS_exit, "exit"),
            (libc::SYS_exit_group, "exit_group"),
        ] {
            a.keep(nr, name, vec![]);
        }
        a
    }

    /// Lot 276: the `export` worker's list — the parse worker's, but its
    /// channel's `sendto` and `recvfrom`, and:
    ///
    /// - its receiver: `socket` (TCP only, IPv4 or IPv6, non-blocking,
    ///   close-on-exec: `nn_export::net::SOCK_FLAGS`), `connect` (its address
    ///   cannot be filtered: Landlock pins the port, from ABI 4 —
    ///   `pin_tcp_connect`), `ppoll`, `getsockopt(SOL_SOCKET, SO_ERROR)`,
    ///   `ioctl(SIOCOUTQ)`, `sendto` with `MSG_NOSIGNAL` and `recvfrom` with no
    ///   flag, both on a descriptor above the channel and with no address;
    /// - its files, in the one directory its Landlock rule names:
    ///   `openat(AT_FDCWD, …)` with exactly `nn_export::jsonl::OPEN_FLAGS`
    ///   (append-only, never through a link), `write` above the channel,
    ///   `lseek`, `fdatasync`, `renameat2(AT_FDCWD, …, AT_FDCWD, …, 0)`,
    ///   `unlinkat(AT_FDCWD, …, 0)`, `newfstatat(AT_FDCWD, …,
    ///   AT_SYMLINK_NOFOLLOW)` (the sink's open: a file an earlier
    ///   configuration left is removed only if it is a regular one — the
    ///   second review of #499, R3);
    /// - the Landlock calls (`landlock_create_ruleset`, `_add_rule`,
    ///   `_restrict_self`): its second layer, the port's pin, made after its
    ///   setup; a layer only ever takes rights away.
    ///
    /// `sock_flags` and `open_flags` are nn-export's (named there, passed
    /// here: nn-linux does not depend on it).
    pub fn export_worker(ipc_fd: RawFd, self_pid: u32, sock_flags: i32, open_flags: i32) -> Self {
        let mut a = Self::default();
        let fd = ipc_fd as u64;
        let above = fd + 1;
        let at_fdcwd = u64::from(libc::AT_FDCWD as u32);
        a.keep(
            libc::SYS_recvfrom,
            "recvfrom",
            vec![
                Arg::Eq(0, fd),
                Arg::Eq(3, crate::worker::transport::WORKER_RECV_FLAGS as u64),
                Arg::Eq64(4, 0),
                Arg::Eq64(5, 0),
            ],
        );
        a.keep(
            libc::SYS_recvfrom,
            "recvfrom (receiver)",
            vec![
                Arg::Ge(0, above),
                Arg::Eq(3, 0),
                Arg::Eq64(4, 0),
                Arg::Eq64(5, 0),
            ],
        );
        a.keep(
            libc::SYS_sendto,
            "sendto",
            vec![
                Arg::Eq(0, fd),
                Arg::Eq(3, crate::worker::transport::WORKER_SEND_FLAGS as u64),
                Arg::Eq64(4, 0),
                Arg::Eq64(5, 0),
            ],
        );
        a.keep(
            libc::SYS_sendto,
            "sendto (receiver)",
            vec![
                Arg::Ge(0, above),
                Arg::Eq(3, libc::MSG_NOSIGNAL as u64),
                Arg::Eq64(4, 0),
                Arg::Eq64(5, 0),
            ],
        );
        a.keep(libc::SYS_write, "write", vec![Arg::Eq(0, 2)]);
        a.keep(libc::SYS_write, "write (file)", vec![Arg::Ge(0, above)]);
        a.keep(libc::SYS_mmap, "mmap", vec![Arg::NoExec(2)]);
        a.keep(libc::SYS_mprotect, "mprotect", vec![Arg::NoExec(2)]);
        a.keep(
            libc::SYS_tgkill,
            "tgkill",
            vec![Arg::Eq(0, u64::from(self_pid))],
        );
        for family in [libc::AF_INET, libc::AF_INET6] {
            a.keep(
                libc::SYS_socket,
                if family == libc::AF_INET {
                    "socket (tcp)"
                } else {
                    "socket (tcp6)"
                },
                vec![
                    Arg::Eq(0, family as u64),
                    Arg::Eq(1, sock_flags as u32 as u64),
                    Arg::Eq(2, 0),
                ],
            );
        }
        a.keep(
            libc::SYS_getsockopt,
            "getsockopt",
            vec![
                Arg::Eq(1, libc::SOL_SOCKET as u64),
                Arg::Eq(2, libc::SO_ERROR as u64),
            ],
        );
        a.keep(
            libc::SYS_ioctl,
            "ioctl",
            vec![Arg::Eq(1, u64::from(libc::TIOCOUTQ as u32))],
        );
        a.keep(
            libc::SYS_openat,
            "openat",
            vec![Arg::Eq(0, at_fdcwd), Arg::Eq(2, open_flags as u32 as u64)],
        );
        a.keep(
            libc::SYS_renameat2,
            "renameat2",
            vec![Arg::Eq(0, at_fdcwd), Arg::Eq(2, at_fdcwd), Arg::Eq(4, 0)],
        );
        a.keep(
            libc::SYS_unlinkat,
            "unlinkat",
            vec![Arg::Eq(0, at_fdcwd), Arg::Eq(2, 0)],
        );
        a.keep(
            libc::SYS_newfstatat,
            "newfstatat",
            vec![
                Arg::Eq(0, at_fdcwd),
                Arg::Eq(3, libc::AT_SYMLINK_NOFOLLOW as u64),
            ],
        );
        for (nr, name) in [
            (libc::SYS_connect, "connect"),
            (libc::SYS_ppoll, "ppoll"),
            (libc::SYS_lseek, "lseek"),
            (libc::SYS_fdatasync, "fdatasync"),
            (libc::SYS_landlock_create_ruleset, "landlock_create_ruleset"),
            (libc::SYS_landlock_add_rule, "landlock_add_rule"),
            (libc::SYS_landlock_restrict_self, "landlock_restrict_self"),
            (libc::SYS_close, "close"),
            (libc::SYS_brk, "brk"),
            (libc::SYS_munmap, "munmap"),
            (libc::SYS_mremap, "mremap"),
            (libc::SYS_madvise, "madvise"),
            (libc::SYS_futex, "futex"),
            (libc::SYS_clock_gettime, "clock_gettime"),
            (libc::SYS_getrandom, "getrandom"),
            (libc::SYS_rt_sigreturn, "rt_sigreturn"),
            (libc::SYS_rt_sigprocmask, "rt_sigprocmask"),
            (libc::SYS_sigaltstack, "sigaltstack"),
            (libc::SYS_restart_syscall, "restart_syscall"),
            (libc::SYS_sched_yield, "sched_yield"),
            (libc::SYS_getpid, "getpid"),
            (libc::SYS_gettid, "gettid"),
            (libc::SYS_exit, "exit"),
            (libc::SYS_exit_group, "exit_group"),
        ] {
            a.keep(nr, name, vec![]);
        }
        a
    }

    /// The names kept, for the documentation's check and the tests.
    pub fn names(&self) -> Vec<&'static str> {
        self.calls.iter().map(|c| c.1).collect()
    }
}

fn target_arch() -> io::Result<TargetArch> {
    TargetArch::try_from(std::env::consts::ARCH)
        .map_err(|e| io::Error::new(io::ErrorKind::Unsupported, e.to_string()))
}

fn invalid(e: seccompiler::BackendError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
}

/// `list` compiled: any call it does not keep kills the process.
pub fn program(list: &Allowlist) -> io::Result<BpfProgram> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    // lot 276: a call may be kept under several argument sets (any of them
    // allows it), never both with and without: an empty set is "any
    // arguments", and a set beside it would narrow it
    for (nr, name, args) in &list.calls {
        let others = list.calls.iter().filter(|c| c.0 == *nr);
        if args.is_empty() && others.count() > 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{name}: kept with and without arguments"),
            ));
        }
    }
    for (nr, _, args) in &list.calls {
        let entry = rules.entry(*nr).or_default();
        if args.is_empty() {
            continue;
        }
        let conds = args
            .iter()
            .map(|a| match *a {
                Arg::Eq(i, v) => {
                    SeccompCondition::new(i, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, v)
                }
                Arg::Eq64(i, v) => {
                    SeccompCondition::new(i, SeccompCmpArgLen::Qword, SeccompCmpOp::Eq, v)
                }
                Arg::NoExec(i) => SeccompCondition::new(
                    i,
                    SeccompCmpArgLen::Dword,
                    SeccompCmpOp::MaskedEq(libc::PROT_EXEC as u64),
                    0,
                ),
                Arg::Ge(i, v) => {
                    SeccompCondition::new(i, SeccompCmpArgLen::Dword, SeccompCmpOp::Ge, v)
                }
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(invalid)?;
        entry.push(SeccompRule::new(conds).map_err(invalid)?);
    }
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        target_arch()?,
    )
    .map_err(invalid)?;
    BpfProgram::try_from(filter).map_err(invalid)
}

/// Compile `list` and install it on every thread of the process (`TSYNC`;
/// a worker has one). Sets `PR_SET_NO_NEW_PRIVS` first.
pub fn install(list: &Allowlist) -> io::Result<()> {
    let prog = program(list)?;
    seccompiler::apply_filter_all_threads(&prog).map_err(|e| io::Error::other(e.to_string()))
}
