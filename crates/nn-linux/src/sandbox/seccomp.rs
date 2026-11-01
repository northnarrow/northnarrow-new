//! The workers' seccomp allowlists (R14a, plan §3.1), compiled to classic
//! BPF by `seccompiler` (pure Rust; no libseccomp).
//!
//! The `parse` worker keeps (plan §3.1's list, narrowed by its arguments):
//!
//! - its channel: `recvmsg` and `sendmsg` on the IPC descriptor only;
//! - `write` to stderr only (its diagnostics reach the agent's journal);
//! - memory: `brk`, `mmap` and `mprotect` without `PROT_EXEC`, `munmap`,
//!   `mremap`, `madvise`; `futex`; `close`;
//! - `clock_gettime`, `getrandom` (std's hash seeds);
//! - signal returns and masks (`rt_sigreturn`, `rt_sigprocmask`,
//!   `sigaltstack`), `restart_syscall`, `sched_yield`;
//! - an abort: `getpid`, `gettid`, and `tgkill` of itself only;
//! - `exit`, `exit_group`.
//!
//! Everything else — `open*`, `socket`, `connect`, `exec*`, `clone*`,
//! `fork`, `kill`, `ptrace`, `bpf`, `prctl`, `read` of any file, `mmap` of
//! executable memory, another architecture's numbers (and x86_64's x32
//! numbers, which match no rule) — kills the whole process
//! (`SECCOMP_RET_KILL_PROCESS`): the core sees it die by `SIGSYS`.

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
    NoExec(u8),
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
        a.keep(libc::SYS_recvmsg, "recvmsg", vec![Arg::Eq(0, fd)]);
        a.keep(libc::SYS_sendmsg, "sendmsg", vec![Arg::Eq(0, fd)]);
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
                Arg::NoExec(i) => SeccompCondition::new(
                    i,
                    SeccompCmpArgLen::Dword,
                    SeccompCmpOp::MaskedEq(libc::PROT_EXEC as u64),
                    0,
                ),
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
