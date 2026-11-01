//! The decision thread's seccomp filter (R14c, plan §3.1): on that thread
//! only (no `TSYNC`), every call allowed but these, which fail with `EPERM`:
//!
//! - `capset` — its sets stay what [`super::enter`] left;
//! - `execve`, `execveat` — it starts no program;
//! - `bpf` — it neither loads nor reads nor writes a kernel object;
//! - `ptrace`, `process_vm_readv`, `process_vm_writev`, `pidfd_getfd` —
//!   the reach into another process its `SYS_PTRACE` would give (it keeps
//!   it to read `/proc/<pid>/exe`).
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

use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule, TargetArch};

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

fn invalid(e: seccompiler::BackendError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, e.to_string())
}

/// The filter compiled.
pub fn program() -> io::Result<BpfProgram> {
    let arch = TargetArch::try_from(std::env::consts::ARCH)
        .map_err(|e| io::Error::new(io::ErrorKind::Unsupported, e.to_string()))?;
    let rules: BTreeMap<i64, Vec<SeccompRule>> = refused()
        .into_iter()
        .map(|(nr, _)| (nr, Vec::new()))
        .collect();
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(invalid)?;
    BpfProgram::try_from(filter).map_err(invalid)
}

/// The filter, on the calling thread only. `seccompiler::apply_filter`
/// sets `PR_SET_NO_NEW_PRIVS` first (the unit sets it for the process; a
/// run outside it needs it for a filter without `CAP_SYS_ADMIN`).
pub fn install_decision() -> io::Result<()> {
    let prog = program()?;
    seccompiler::apply_filter(&prog).map_err(|e| io::Error::other(e.to_string()))
}
