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

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_task, bpf_ktime_get_ns, bpf_probe_read_kernel},
    maps::LruHashMap,
};
use northnarrow_common::wire::InodeKey;

use crate::btf_offsets::TASK_STRUCT_START_TIME_OFFSET;

/// A read-only open of the same file by the same task within this window
/// is a repeat.
pub const READ_REPEAT_NS: u64 = 1_000_000_000;

/// `(task, inode)`: the key of a [`repeat`] map.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReadSeenKey {
    pid_tgid: u64,
    start_time: u64,
    dev: u64,
    ino: u64,
}

/// `true` when the current task reported a read-only open of `key` less
/// than [`READ_REPEAT_NS`] ago; otherwise remember this open and return
/// `false`. An LRU eviction only makes a repeat report again.
#[inline(always)]
pub unsafe fn repeat(seen: &LruHashMap<ReadSeenKey, u64>, key: &InodeKey) -> bool {
    let task = bpf_get_current_task() as *const u8;
    let start_time = if task.is_null() {
        0
    } else {
        bpf_probe_read_kernel::<u64>(task.add(off!(TASK_STRUCT_START_TIME_OFFSET)) as *const u64).unwrap_or(0)
    };
    let k = ReadSeenKey {
        pid_tgid: bpf_get_current_pid_tgid(),
        start_time,
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
