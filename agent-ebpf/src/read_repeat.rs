//! Repeated read-only opens of one file by one task (review 75).
//!
//! The `file_open` hook reports every open of a watched inode (FIM
//! `Opened`) and every open the file-open sensor classifies. A task that
//! reads the same file again a moment later adds nothing a rule or an
//! analyst can use, and a loop of such reads — of the caller's own
//! credential file, or of a world-readable sensitive file such as
//! `/etc/passwd` — filled the rings and the agent's event channel: an
//! unprivileged user blinded FIM and the sensor for the whole host.
//!
//! [`repeat`] drops those repeats before the ring. A task is its
//! `pid_tgid` and its `start_time`, so a reused pid is a new task. Writes
//! never come here: every write-open still reports.
//!
//! Lot 1.4 (plan S1, F7; the review of #587, P2): a task is also its
//! IMAGE — the `mm` and the executable's inode the last exec gave it. The
//! readers of a credential file are judged by the file the kernel executed,
//! and a reader that ran a quiet program first and then executed another
//! in its place (same pid, same `start_time`) had its read of the same file
//! within the second dropped as a repeat of the first: no record under the
//! program that read. An exec makes a new `mm` while the old one is still
//! in use, so the image after any exec differs from the one before it; the
//! executable's inode (held by the image while it runs) keeps two programs
//! apart even when the kernel's allocator hands the second exec the first
//! one's `mm` again. What stays a repeat after an exec: the SAME executable
//! run again within the second whose new `mm` lands where the first image's
//! was — its read is the one already recorded under that program.

use aya_ebpf::{
    cty::c_void,
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_ktime_get_ns, generated},
    maps::LruHashMap,
};
use northnarrow_common::wire::InodeKey;

use crate::btf_offsets::{
    FILE_F_INODE_OFFSET, MM_STRUCT_EXE_FILE_OFFSET, TASK_STRUCT_MM_OFFSET, TASK_STRUCT_START_TIME_OFFSET,
};

/// A read-only open of the same file by the same task within this window
/// is a repeat.
pub const READ_REPEAT_NS: u64 = 1_000_000_000;

/// `(task, image, inode)`: the key of a [`repeat`] map. Six words, no
/// padding: every byte of a key is written.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReadSeenKey {
    pid_tgid: u64,
    start_time: u64,
    /// Lot 1.4 (F7): the task's `mm` (0 for a kernel thread)…
    mm: u64,
    /// … and its executable's inode (`mm->exe_file->f_inode`; 0 when the
    /// task has none).
    exe_inode: u64,
    dev: u64,
    ino: u64,
}

/// The `u64` at kernel address `src`, 0 when it cannot be read: the helper
/// zeroes its destination on a fault, so the value needs no branch (each
/// one would add states to the hot `file_open` programs). A null or small
/// `src` — the field of a task with no `mm`, of an image with no
/// executable — is such a fault.
#[inline(always)]
unsafe fn peek(src: u64) -> u64 {
    // SAFETY: the helper writes the 8 bytes of `v` in every case (the value
    // read, or zeros), before `assume_init`; `src` is only passed to it.
    unsafe {
        let mut v = core::mem::MaybeUninit::<u64>::uninit();
        let _ = generated::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 8, src as *const c_void);
        v.assume_init()
    }
}

/// `true` when the current task, in its current image, reported a
/// read-only open of `key` less than [`READ_REPEAT_NS`] ago; otherwise
/// remember this open and return `false`. An LRU eviction only makes a
/// repeat report again.
#[inline(always)]
pub unsafe fn repeat(seen: &LruHashMap<ReadSeenKey, u64>, key: &InodeKey) -> bool {
    // SAFETY: the running task's `task_struct`, its `mm` and the image's
    // `struct file` are read only through `bpf_probe_read_kernel` ([`peek`]:
    // a fault reads 0); nothing is written through them. The map's key and
    // value are this function's own stack values.
    unsafe {
        let task = bpf_get_current_task();
        let mm = peek(task + off!(TASK_STRUCT_MM_OFFSET) as u64);
        let exe_file = peek(mm + off!(MM_STRUCT_EXE_FILE_OFFSET) as u64);
        let k = ReadSeenKey {
            pid_tgid: bpf_get_current_pid_tgid(),
            start_time: peek(task + off!(TASK_STRUCT_START_TIME_OFFSET) as u64),
            mm,
            exe_inode: peek(exe_file + off!(FILE_F_INODE_OFFSET) as u64),
            dev: key.dev,
            ino: key.ino,
        };
        let now = bpf_ktime_get_ns();
        if let Some(last) = seen.get(&k) {
            if now.wrapping_sub(*last) < READ_REPEAT_NS {
                return true;
            }
        }
        let _ = seen.insert(&k, &now, 0);
        false
    }
}

/// [`nn_read_repeat`]'s map: the FIM watch's (`fim_watch::FIM_READ_SEEN`)…
pub const SEEN_FIM: u64 = 0;
/// … or the file-open sensor's (`open_sensor::OPEN_READ_SEEN`).
pub const SEEN_OPEN: u64 = 1;

/// Lot 1.4b (stack): [`repeat`] as a global BPF function — 1 for a repeat,
/// 0 otherwise — for the `file_open` sensor's two call sites
/// (`open_sensor::on_open_in`, `nn_open_observe`). Its key (six words) and
/// time are on this function's own frame, not on the sensor program's:
/// inline, they took `fim_file_open_sensor`'s frame from 160 to 192 bytes
/// and its deepest chain past the 448 of the gate. Every argument is a
/// plain value (`which` one of [`SEEN_FIM`], [`SEEN_OPEN`]; the inode's
/// device and number), so the verifier checks it once, for any value.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn nn_read_repeat(which: u64, dev: u64, ino: u64) -> u64 {
    let key = InodeKey { dev, ino };
    // SAFETY: [`repeat`]'s reads of the running task (helpers only).
    let seen = unsafe {
        if which == SEEN_OPEN {
            repeat(&crate::open_sensor::OPEN_READ_SEEN, &key)
        } else {
            repeat(&crate::fim_watch::FIM_READ_SEEN, &key)
        }
    };
    u64::from(seen)
}

