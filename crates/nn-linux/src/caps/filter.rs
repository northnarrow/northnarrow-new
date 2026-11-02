//! The decision thread's seccomp filter (R14c, plan §3.1): on that thread
//! only (no `TSYNC`), every call allowed but these, which fail with `EPERM`:
//!
//! - `capset` — its sets stay what [`super::enter`] left;
//! - `execve`, `execveat` — it starts no program;
//! - `bpf` — it neither loads nor reads nor writes a kernel object;
//! - `ptrace`, `process_vm_readv`, `process_vm_writev`, `pidfd_getfd` —
//!   the reach into another process its `SYS_PTRACE` would give (it keeps
//!   it to read `/proc/<pid>/exe`);
//! - review of #482 (R14c-1): a file opened for writing — `open` and
//!   `openat` with `O_WRONLY`, `O_RDWR`, `O_CREAT` or `O_TRUNC`, `creat`,
//!   and `openat2` whatever it asks (its flags are in user memory, which a
//!   filter cannot read; nothing of the agent uses it). `SYS_PTRACE` with
//!   uid 0 opens another root process's `/proc/<pid>/mem` for writing, and
//!   uid 0 owns the keys, `/etc/ld.so.preload` and the units: the decision
//!   writes no file (the canary is the writer's, the detections go by a
//!   channel — lot 272's lab trace saw no such open by it);
//! - a signal to another process — `kill`, `tgkill`, `rt_sigqueueinfo`,
//!   `rt_tgsigqueueinfo` to another thread group than the agent's (a pid of
//!   0 or below is a group: refused), `tkill` and `pidfd_send_signal`
//!   whatever their target (a thread id, a descriptor: the filter cannot
//!   tell whose). With uid 0, `kill(2)` reaches every root process without
//!   `CAP_KILL`; the agent's own (an abort's `tgkill`) stay allowed.
//!
//! What it does not refuse (`docs/architecture/PROCESS_MODEL.md` §8): the
//! other calls that change a file by its path — `unlink`, `rename`,
//! `chmod`, `truncate`… — on a root-owned file (uid 0 owns them; Open: a
//! read-only Landlock domain for the thread, or the `/proc` broker), and
//! reading another process's open files through `/proc/<pid>/fd/N`.
//!
//! `EPERM`, not a kill: the decision thread is the agent's judgement, and a
//! crafted event that steers it into one of these calls must not become a
//! way to stop the agent; the call fails, the caller reports its error.
//! On x86_64 the same calls under the x32 numbers are refused too (the
//! unit's `SystemCallArchitectures=native` refuses x32 for the whole
//! process as well); a call of another architecture (`int 0x80`) is
//! seccompiler's architecture check: the process is killed.

use std::collections::BTreeMap;
use std::io;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};

/// x86_64's x32 bit.
#[cfg(target_arch = "x86_64")]
const X32: i64 = 0x4000_0000;

/// The refused calls: `(number, name)`.
pub fn refused() -> Vec<(i64, &'static str)> {
    #[allow(unused_mut)]
    let mut v: Vec<(i64, &'static str)> = vec![
        (libc::SYS_capset, "capset"),
        (libc::SYS_execve, "execve"),
        (libc::SYS_execveat, "execveat"),
        (libc::SYS_bpf, "bpf"),
        (libc::SYS_ptrace, "ptrace"),
        (libc::SYS_process_vm_readv, "process_vm_readv"),
        (libc::SYS_process_vm_writev, "process_vm_writev"),
        (libc::SYS_pidfd_getfd, "pidfd_getfd"),
    ];
    #[cfg(target_arch = "x86_64")]
    {
        // the x32 table's own numbers where it has them (arch/x86/entry/
        // syscalls/syscall_64.tbl: 512 and up), the common ones otherwise
        v.extend([
            (X32 | libc::SYS_capset, "capset (x32)"),
            (X32 | 520, "execve (x32)"),
            (X32 | 545, "execveat (x32)"),
            (X32 | libc::SYS_bpf, "bpf (x32)"),
            (X32 | 521, "ptrace (x32)"),
            (X32 | 539, "process_vm_readv (x32)"),
            (X32 | 540, "process_vm_writev (x32)"),
            (X32 | libc::SYS_pidfd_getfd, "pidfd_getfd (x32)"),
        ]);
    }
    v
}

/// Review of #482 (R14c-1): what is refused on a condition of a call's
/// argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum When {
    /// The open's flags (the argument's index) ask to write, create or
    /// truncate.
    OpensToWrite(u8),
    /// The first argument (a thread group) is not the agent's.
    NotOurs,
}

/// The calls refused on a condition: `(number, name, condition)`.
pub fn refused_when() -> Vec<(i64, &'static str, When)> {
    #[allow(unused_mut)]
    let mut v: Vec<(i64, &'static str, When)> = Vec::new();
    #[cfg(target_arch = "x86_64")]
    v.push((libc::SYS_open, "open", When::OpensToWrite(1)));
    v.extend([
        (libc::SYS_openat, "openat", When::OpensToWrite(2)),
        (libc::SYS_kill, "kill", When::NotOurs),
        (libc::SYS_tgkill, "tgkill", When::NotOurs),
        (libc::SYS_rt_sigqueueinfo, "rt_sigqueueinfo", When::NotOurs),
        (
            libc::SYS_rt_tgsigqueueinfo,
            "rt_tgsigqueueinfo",
            When::NotOurs,
        ),
    ]);
    #[cfg(target_arch = "x86_64")]
    {
        v.extend([
            (X32 | libc::SYS_open, "open (x32)", When::OpensToWrite(1)),
            (
                X32 | libc::SYS_openat,
                "openat (x32)",
                When::OpensToWrite(2),
            ),
            (X32 | libc::SYS_kill, "kill (x32)", When::NotOurs),
            (X32 | libc::SYS_tgkill, "tgkill (x32)", When::NotOurs),
            (X32 | 524, "rt_sigqueueinfo (x32)", When::NotOurs),
            (X32 | 536, "rt_tgsigqueueinfo (x32)", When::NotOurs),
        ]);
    }
    v
}

/// The calls refused whatever their arguments, beyond [`refused`]'s: the
/// writing opens and the signals a filter cannot judge (review of #482,
/// R14c-1).
pub fn refused_always() -> Vec<(i64, &'static str)> {
    #[allow(unused_mut)]
    let mut v: Vec<(i64, &'static str)> = Vec::new();
    #[cfg(target_arch = "x86_64")]
    v.push((libc::SYS_creat, "creat"));
    v.extend([
        (libc::SYS_openat2, "openat2"),
        (libc::SYS_tkill, "tkill"),
        (libc::SYS_pidfd_send_signal, "pidfd_send_signal"),
    ]);
    #[cfg(target_arch = "x86_64")]
    {
        v.extend([
            (X32 | libc::SYS_creat, "creat (x32)"),
            (X32 | libc::SYS_openat2, "openat2 (x32)"),
            (X32 | libc::SYS_tkill, "tkill (x32)"),
            (X32 | libc::SYS_pidfd_send_signal, "pidfd_send_signal (x32)"),
        ]);
    }
    v
}

fn invalid(e: seccompiler::BackendError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
}

fn rules_of(when: When, tgid: u32) -> io::Result<Vec<SeccompRule>> {
    let cond = |arg: u8, op: SeccompCmpOp, value: u64| {
        SeccompCondition::new(arg, SeccompCmpArgLen::Dword, op, value).map_err(invalid)
    };
    let rule = |c: SeccompCondition| SeccompRule::new(vec![c]).map_err(invalid);
    match when {
        When::OpensToWrite(arg) => {
            let acc = libc::O_ACCMODE as u64;
            let mut v = Vec::new();
            // O_WRONLY, O_RDWR, and the invalid 3 (it asks for both)
            for mode in [libc::O_WRONLY as u64, libc::O_RDWR as u64, acc] {
                v.push(rule(cond(arg, SeccompCmpOp::MaskedEq(acc), mode)?)?);
            }
            for flag in [libc::O_CREAT as u64, libc::O_TRUNC as u64] {
                v.push(rule(cond(arg, SeccompCmpOp::MaskedEq(flag), flag)?)?);
            }
            Ok(v)
        }
        When::NotOurs => Ok(vec![rule(cond(0, SeccompCmpOp::Ne, u64::from(tgid))?)?]),
    }
}

/// The filter compiled, for the process `tgid` (the agent's: a signal to
/// itself is allowed).
pub fn program_for(tgid: u32) -> io::Result<BpfProgram> {
    let arch = TargetArch::try_from(std::env::consts::ARCH)
        .map_err(|e| io::Error::new(io::ErrorKind::Unsupported, e.to_string()))?;
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = refused()
        .into_iter()
        .chain(refused_always())
        .map(|(nr, _)| (nr, Vec::new()))
        .collect();
    for (nr, _, when) in refused_when() {
        rules.insert(nr, rules_of(when, tgid)?);
    }
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(invalid)?;
    BpfProgram::try_from(filter).map_err(invalid)
}

/// The filter compiled for this process.
pub fn program() -> io::Result<BpfProgram> {
    program_for(std::process::id())
}

/// The filter, on the calling thread only. `seccompiler::apply_filter`
/// sets `PR_SET_NO_NEW_PRIVS` first (the unit sets it for the process; a
/// run outside it needs it for a filter without `CAP_SYS_ADMIN`).
pub fn install_decision() -> io::Result<()> {
    let prog = program()?;
    seccompiler::apply_filter(&prog).map_err(|e| io::Error::other(e.to_string()))
}
