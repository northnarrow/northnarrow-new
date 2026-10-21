//! The scanner's seccomp filter (lab PR 223): what a process that parses
//! hostile files may still ask of the kernel.
//!
//! Allowed: reading and closing the descriptors it is handed (`read`,
//! `pread64`, `lseek`, `fstat`, `close`), the channel to the agent
//! (`recvmsg`, `sendmsg`), memory (`brk`, `mmap` / `mprotect` without
//! `PROT_EXEC`, `munmap`, `mremap`, `madvise`), `futex`, the clock,
//! `getrandom`, signal returns and masks, `write` to stderr only, `tgkill`
//! to itself only (an abort), `fcntl(F_GETFD)` only, and exit. Everything else — `open*`, `exec*`,
//! `socket`, `connect`, `clone`, `ptrace`, `bpf`, `mmap` of executable
//! memory, any other architecture's system call numbers — kills the whole
//! process (`SECCOMP_RET_KILL_PROCESS`): the agent sees it exit and
//! applies its default policy to what was pending.
//!
//! Classic BPF built by hand (no libseccomp: no C in production).

use std::io;

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_JGE: u16 = 0x30;
const BPF_JSET: u16 = 0x40;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;

/// `struct seccomp_data` offsets.
const OFF_NR: u32 = 0;
const OFF_ARCH: u32 = 4;
const fn off_arg_lo(i: u32) -> u32 {
    16 + 8 * i
}

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7;

/// The x32 ABI's flag in x86_64 system call numbers.
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// System calls allowed whatever their arguments.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn plain() -> Vec<libc::c_long> {
    vec![
        libc::SYS_read,
        libc::SYS_pread64,
        libc::SYS_lseek,
        libc::SYS_fstat,
        libc::SYS_close,
        libc::SYS_recvmsg,
        libc::SYS_sendmsg,
        libc::SYS_brk,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_futex,
        libc::SYS_sched_yield,
        libc::SYS_clock_gettime,
        libc::SYS_getrandom,
        libc::SYS_rt_sigreturn,
        libc::SYS_rt_sigprocmask,
        libc::SYS_sigaltstack,
        libc::SYS_restart_syscall,
        libc::SYS_getpid,
        libc::SYS_gettid,
        libc::SYS_exit,
        libc::SYS_exit_group,
    ]
}

/// The filter for a process whose pid is `self_pid`.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub fn program(self_pid: u32) -> Vec<libc::sock_filter> {
    let kill = stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    let allow = stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    let mut p = vec![
        stmt(BPF_LD | BPF_W | BPF_ABS, OFF_ARCH),
        jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH, 1, 0),
        kill,
        stmt(BPF_LD | BPF_W | BPF_ABS, OFF_NR),
    ];
    #[cfg(target_arch = "x86_64")]
    {
        p.push(jump(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1));
        p.push(kill);
    }
    // Plain allows jump to the final ALLOW; patched once its index is known.
    let plain = plain();
    let first_plain = p.len();
    for nr in &plain {
        p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, *nr as u32, 0, 0));
    }
    // `nr` with argument `arg` checked: allowed when `ok(arg)`.
    // Block: jeq nr (else skip 4) · ld arg · test · ret KILL · ret ALLOW.
    let block =
        |p: &mut Vec<libc::sock_filter>, nr: libc::c_long, arg: u32, test: libc::sock_filter| {
            p.push(jump(BPF_JMP | BPF_JEQ | BPF_K, nr as u32, 0, 4));
            p.push(stmt(BPF_LD | BPF_W | BPF_ABS, off_arg_lo(arg)));
            p.push(test);
            p.push(kill);
            p.push(allow);
        };
    // mmap / mprotect: never executable memory (jset → KILL, else ALLOW).
    let no_exec = jump(BPF_JMP | BPF_JSET | BPF_K, libc::PROT_EXEC as u32, 0, 1);
    block(&mut p, libc::SYS_mmap, 2, no_exec);
    block(&mut p, libc::SYS_mprotect, 2, no_exec);
    // write: stderr only (jeq 2 → skip the KILL).
    block(
        &mut p,
        libc::SYS_write,
        0,
        jump(BPF_JMP | BPF_JEQ | BPF_K, 2, 1, 0),
    );
    // fcntl: F_GETFD only (std's debug builds check a descriptor is open
    // before closing it; nothing else is needed).
    block(
        &mut p,
        libc::SYS_fcntl,
        1,
        jump(BPF_JMP | BPF_JEQ | BPF_K, libc::F_GETFD as u32, 1, 0),
    );
    // tgkill: itself only (abort).
    block(
        &mut p,
        libc::SYS_tgkill,
        0,
        jump(BPF_JMP | BPF_JEQ | BPF_K, self_pid, 1, 0),
    );
    p.push(kill);
    let allow_at = p.len();
    p.push(allow);
    for i in 0..plain.len() {
        let at = first_plain + i;
        p[at].jt = u8::try_from(allow_at - at - 1).expect("filter jump fits");
    }
    p
}

/// Install `prog` on the calling thread (no allocation: safe after
/// `fork()`). Sets `PR_SET_NO_NEW_PRIVS` first, which an unprivileged
/// process needs for a filter.
pub fn install_program(prog: &[libc::sock_filter]) -> io::Result<()> {
    // SAFETY: prctl with integer arguments.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let fprog = libc::sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_ptr() as *mut libc::sock_filter,
    };
    // SAFETY: seccomp(2) with a filter program that outlives the call.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            0 as libc::c_ulong,
            &fprog as *const libc::sock_fprog,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Build and install the filter for this process.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub fn install() -> io::Result<()> {
    let prog = program(std::process::id());
    install_program(&prog)
}

/// No filter for this architecture: the scanner refuses to run.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn install() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no seccomp filter for this architecture",
    ))
}

#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
mod tests {
    use super::*;

    /// Run `body` in a forked child under the filter; its wait status.
    /// The program is built before the fork (no allocation in the child).
    fn under_filter(body: fn() -> i32) -> i32 {
        // the child's own pid is not known before the fork: build for a
        // pid no process has (tgkill is then refused, which no body uses)
        let prog = program(u32::MAX);
        // SAFETY: fork; the child calls only async-signal-safe syscalls.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork");
        if pid == 0 {
            if install_program(&prog).is_err() {
                // SAFETY: _exit in the child.
                unsafe { libc::_exit(100) };
            }
            let rc = body();
            // SAFETY: _exit in the child.
            unsafe { libc::_exit(rc) };
        }
        let mut status = 0;
        // SAFETY: waiting for our own child.
        unsafe { libc::waitpid(pid, &mut status, 0) };
        status
    }

    fn killed_by_sigsys(status: i32) -> bool {
        libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGSYS
    }

    #[test]
    fn allowed_calls_run_and_exit_cleanly() {
        let s = under_filter(|| {
            let mut buf = [0u8; 8];
            // read of a pipe-less fd fails with EBADF but is allowed
            // SAFETY: plain syscalls.
            unsafe {
                libc::syscall(libc::SYS_read, -1, buf.as_mut_ptr(), 8);
                libc::syscall(libc::SYS_write, 2, b"".as_ptr(), 0);
                let m = libc::syscall(
                    libc::SYS_mmap,
                    0,
                    4096,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                libc::syscall(libc::SYS_munmap, m, 4096);
            }
            7
        });
        assert!(
            libc::WIFEXITED(s) && libc::WEXITSTATUS(s) == 7,
            "status {s:#x}"
        );
    }

    #[test]
    fn opening_a_file_kills_the_process() {
        let s = under_filter(|| {
            // SAFETY: plain syscall with a static C string.
            unsafe {
                libc::syscall(
                    libc::SYS_openat,
                    libc::AT_FDCWD,
                    c"/etc/hostname".as_ptr(),
                    libc::O_RDONLY,
                )
            };
            0
        });
        assert!(killed_by_sigsys(s), "status {s:#x}");
    }

    #[test]
    fn a_socket_kills_the_process() {
        let s = under_filter(|| {
            // SAFETY: plain syscall.
            unsafe { libc::syscall(libc::SYS_socket, libc::AF_INET, libc::SOCK_STREAM, 0) };
            0
        });
        assert!(killed_by_sigsys(s), "status {s:#x}");
    }

    #[test]
    fn executable_memory_and_stdout_kill_the_process() {
        let s = under_filter(|| {
            // SAFETY: plain syscall.
            unsafe {
                libc::syscall(
                    libc::SYS_mmap,
                    0,
                    4096,
                    libc::PROT_READ | libc::PROT_EXEC,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            0
        });
        assert!(killed_by_sigsys(s), "mmap PROT_EXEC: status {s:#x}");
        let s = under_filter(|| {
            // SAFETY: plain syscall.
            unsafe { libc::syscall(libc::SYS_write, 1, b"x".as_ptr(), 1) };
            0
        });
        assert!(killed_by_sigsys(s), "write(1): status {s:#x}");
    }

    #[test]
    fn the_program_is_well_formed() {
        let p = program(42);
        assert!(p.len() < 100);
        assert_eq!(p.last().unwrap().k, SECCOMP_RET_ALLOW);
        assert_eq!(p[p.len() - 2].k, SECCOMP_RET_KILL_PROCESS);
        // every jump lands inside the program
        for (i, ins) in p.iter().enumerate() {
            if ins.code & 0x07 == BPF_JMP {
                assert!(i + 1 + (ins.jt as usize) < p.len(), "jt at {i}");
                assert!(i + 1 + (ins.jf as usize) < p.len(), "jf at {i}");
            }
        }
    }
}
