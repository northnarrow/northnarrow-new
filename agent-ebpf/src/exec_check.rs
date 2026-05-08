//! Pre-exec validation sensor.
//!
//! **Deviation from spec:** uses `syscalls/sys_enter_execve` instead
//! of the LSM `bprm_check_security` hook, for the same reason as
//! `file_open` — bpf-linker 0.10 doesn't emit BTF, so LSM CO-RE
//! reloc would fail at load time. The tracepoint gives userland
//! every field listed in the spec (pid, uid, comm, filename) and
//! fires at the same moment in the exec path (after copy_strings,
//! before the new image starts). Real `-EPERM` enforcement is a
//! Tappa 7 task anyway.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns, bpf_probe_read_user_str_bytes,
    },
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use northnarrow_common::wire::{ExecCheckRaw, FILENAME_LEN, TASK_COMM_LEN};

#[map]
static EXEC_CHECK_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// sys_enter_execve event format:
//   field:int            __syscall_nr;  offset:8;
//   field:const char *   filename;      offset:16;
//   field:const char *const * argv;     offset:24;
//   field:const char *const * envp;     offset:32;
const FILENAME_PTR_OFFSET: usize = 16;

#[tracepoint]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    let _ = try_sys_enter_execve(&ctx);
    0
}

#[inline(always)]
fn try_sys_enter_execve(ctx: &TracePointContext) -> Result<(), i64> {
    let mut entry = match EXEC_CHECK_EVENTS.reserve::<ExecCheckRaw>(0) {
        Some(e) => e,
        None => return Ok(()),
    };
    let raw_ptr: *mut ExecCheckRaw = entry.as_mut_ptr();
    unsafe {
        core::ptr::write_bytes(raw_ptr, 0u8, 1);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let filename_ptr = unsafe { ctx.read_at::<u64>(FILENAME_PTR_OFFSET) }.unwrap_or(0);

    unsafe {
        (*raw_ptr).pid = (pid_tgid >> 32) as u32;
        // ppid is left 0; needs CO-RE on task->real_parent->tgid.
        (*raw_ptr).uid = (uid_gid & 0xFFFF_FFFF) as u32;
        (*raw_ptr).timestamp_ns = bpf_ktime_get_ns();
    }

    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    unsafe {
        let dst = (*raw_ptr).comm.as_mut_ptr();
        let src = comm.as_ptr();
        let mut i = 0usize;
        while i < TASK_COMM_LEN {
            *dst.add(i) = *src.add(i);
            i += 1;
        }
    }

    if filename_ptr != 0 {
        unsafe {
            let dst = core::slice::from_raw_parts_mut(
                (*raw_ptr).filename.as_mut_ptr(),
                FILENAME_LEN,
            );
            let _ = bpf_probe_read_user_str_bytes(filename_ptr as *const u8, dst);
        }
    }

    entry.submit(0);
    Ok(())
}
