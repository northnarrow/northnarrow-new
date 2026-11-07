//! Lot 290: the cross-view's kernel half.
//!
//! * "Seen": a `BPF_PROG_LOAD` the `bpf` hook lets through marks its thread
//!   ([`mark_load`]); the `bpf_prog` hook, which the kernel calls when the
//!   load hands the new program's descriptor out (its id assigned), takes
//!   the mark ([`take_load_mark`]) and records the program's id with its
//!   loader ([`mark_seen`], [`SEEN_PROGS`]). A thread's mark is cleared by
//!   its next command that may hand out a program descriptor of another
//!   program (`BPF_PROG_GET_FD_BY_ID`, `BPF_OBJ_GET`), so a load the
//!   verifier refused never marks another program. The agent's family is
//!   not marked (its programs are its own).
//! * "Enumerated": two BPF iterators the agent runs every round —
//!   `iter/bpf_prog` ([`census_progs`]) writes one
//!   [`ProgRecord`] per program loaded on the host, `iter/bpf_link`
//!   ([`census_links`], kernels that have it) one [`LinkRecord`] per link.
//!   The agent's unit has no `CAP_SYS_ADMIN`, which `BPF_*_GET_NEXT_ID`
//!   needs; an iterator needs `CAP_BPF` and `CAP_PERFMON`, which it has.
//!
//! The agent compares the two (`crates/nn-linux/src/bpf_crossview.rs`).

use aya_ebpf::{
    cty::c_void,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_kernel,
        bpf_probe_read_kernel_str_bytes, generated::bpf_seq_write,
    },
    macros::map,
    maps::{LruHashMap, PerCpuArray},
};
use northnarrow_common::bpf_prog_class::{LinkRecord, ProgRecord, SeenLoad, ATTACH_NAME_LEN};

use crate::btf_offsets::{
    BPF_LINK_ID_OFFSET, BPF_LINK_PROG_OFFSET, BPF_LINK_TYPE_OFFSET, BPF_PROG_AUX_ATTACH_FUNC_NAME_OFFSET,
    BPF_PROG_AUX_ID_OFFSET, BPF_PROG_AUX_LOAD_TIME_OFFSET, BPF_PROG_AUX_NAME_OFFSET, BPF_PROG_AUX_OFFSET, BPF_PROG_EXPECTED_ATTACH_TYPE_OFFSET, BPF_PROG_TAG_OFFSET,
    BPF_PROG_TYPE_OFFSET,
};

/// Threads in a `BPF_PROG_LOAD` the `bpf` hook let through (thread id →
/// 1). LRU: a mark a refused load left is evicted in time, and cleared by
/// the thread's next handle command anyway.
#[map]
static PROG_LOAD_INFLIGHT: LruHashMap<u32, u32> = LruHashMap::with_max_entries(1024, 0);

/// The programs the `bpf` hook saw loading since the agent's start (id →
/// loader). The agent copies it every round, so an entry the LRU evicts
/// after that copy is not lost; 8192 loads between two rounds (5 s) would
/// be.
#[map]
pub static SEEN_PROGS: LruHashMap<u32, SeenLoad> = LruHashMap::with_max_entries(8192, 0);

/// The iterators' record scratch (a 104-byte record on the stack lowers
/// its zeroing to a `memset` subprogram the 5.15 verifier refuses).
#[map]
static PROG_RECORD_SCRATCH: PerCpuArray<ProgRecord> = PerCpuArray::with_max_entries(1, 0);

/// The calling thread is in a load the hook let through.
#[inline(always)]
pub fn mark_load() {
    let tid = bpf_get_current_pid_tgid() as u32;
    let _ = PROG_LOAD_INFLIGHT.insert(&tid, &1, 0);
}

/// The calling thread's command is not a load.
#[inline(always)]
pub fn clear_load_mark() {
    let tid = bpf_get_current_pid_tgid() as u32;
    let _ = PROG_LOAD_INFLIGHT.remove(&tid);
}

/// Whether the calling thread was in a load the hook let through (the
/// mark taken away).
#[inline(always)]
pub fn take_load_mark() -> bool {
    let tid = bpf_get_current_pid_tgid() as u32;
    let marked = unsafe { PROG_LOAD_INFLIGHT.get(&tid) }.is_some();
    if marked {
        let _ = PROG_LOAD_INFLIGHT.remove(&tid);
    }
    marked
}

/// Program `id` (`prog`) was just loaded by the calling process.
#[inline(always)]
pub unsafe fn mark_seen(id: u32, prog: *const c_void) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let seen = SeenLoad {
        tgid: (pid_tgid >> 32) as u32,
        uid: bpf_get_current_uid_gid() as u32,
        prog_type: rd_u32(prog as u64 + off!(BPF_PROG_TYPE_OFFSET) as u64).unwrap_or(u32::MAX),
        _pad: 0,
        comm: bpf_get_current_comm().unwrap_or([0u8; 16]),
    };
    let _ = SEEN_PROGS.insert(&id, &seen, 0);
}

#[inline(always)]
unsafe fn rd_u32(addr: u64) -> Option<u32> {
    bpf_probe_read_kernel::<u32>(addr as *const u32).ok()
}

#[inline(always)]
unsafe fn rd_u64(addr: u64) -> Option<u64> {
    bpf_probe_read_kernel::<u64>(addr as *const u64).ok()
}

/// `iter/bpf_prog`: one [`ProgRecord`] per program. The context is
/// `struct bpf_iter__bpf_prog { struct bpf_iter_meta *meta; struct bpf_prog
/// *prog; }`; the last call has no program. The seq file is read through
/// the typed pointers (`bpf_seq_write` takes it as such); every field of
/// the program through `bpf_probe_read_kernel` and the offsets resolved
/// at boot. A field whose offset is absent stays zero.
#[no_mangle]
#[link_section = "iter/bpf_prog"]
pub fn census_progs(ctx: *mut c_void) -> i32 {
    unsafe { try_iter_progs(ctx) };
    0
}

#[inline(always)]
unsafe fn try_iter_progs(ctx: *mut c_void) {
    let meta = *(ctx as *const *const *mut c_void);
    let prog = *(ctx as *const u64).add(1);
    if prog == 0 || meta.is_null() {
        return;
    }
    let seq = *meta;
    let rec: *mut ProgRecord = match PROG_RECORD_SCRATCH.get_ptr_mut(0) {
        Some(p) => p,
        None => return,
    };
    crate::zero::zero(rec);
    let Some(aux) = rd_u64(prog + off!(BPF_PROG_AUX_OFFSET) as u64) else {
        return;
    };
    if aux == 0 {
        return;
    }
    let Some(id) = rd_u32(aux + off!(BPF_PROG_AUX_ID_OFFSET) as u64) else {
        return;
    };
    (*rec).id = id;
    (*rec).prog_type = rd_u32(prog + off!(BPF_PROG_TYPE_OFFSET) as u64).unwrap_or(u32::MAX);
    if let Some(o) = off_opt!(BPF_PROG_EXPECTED_ATTACH_TYPE_OFFSET) {
        (*rec).expected_attach_type = rd_u32(prog + o as u64).unwrap_or(u32::MAX);
    }
    if let Some(o) = off_opt!(BPF_PROG_TAG_OFFSET) {
        if let Ok(tag) = bpf_probe_read_kernel::<[u8; 8]>((prog + o as u64) as *const [u8; 8]) {
            (*rec).tag = tag;
        }
    }
    if let Some(o) = off_opt!(BPF_PROG_AUX_LOAD_TIME_OFFSET) {
        (*rec).load_time = rd_u64(aux + o as u64).unwrap_or(0);
    }
    if let Some(o) = off_opt!(BPF_PROG_AUX_NAME_OFFSET) {
        if let Ok(name) = bpf_probe_read_kernel::<[u8; 16]>((aux + o as u64) as *const [u8; 16]) {
            (*rec).name = name;
        }
    }
    if let Some(o) = off_opt!(BPF_PROG_AUX_ATTACH_FUNC_NAME_OFFSET) {
        if let Some(p) = rd_u64(aux + o as u64) {
            if p != 0 {
                let dst: &mut [u8; ATTACH_NAME_LEN] = &mut (*rec).attach;
                if bpf_probe_read_kernel_str_bytes(p as *const u8, dst).is_ok() {
                    (*rec).attach_read = 1;
                }
            }
        }
    }
    bpf_seq_write(
        seq as *mut aya_ebpf::bindings::seq_file,
        rec as *const c_void,
        core::mem::size_of::<ProgRecord>() as u32,
    );
}

/// `iter/bpf_link`: one [`LinkRecord`] per link (`struct bpf_iter__bpf_link
/// { struct bpf_iter_meta *meta; struct bpf_link *link; }`). Kernels
/// without the link iterator do not load it; the agent then enumerates the
/// programs only.
#[no_mangle]
#[link_section = "iter/bpf_link"]
pub fn census_links(ctx: *mut c_void) -> i32 {
    unsafe { try_iter_links(ctx) };
    0
}

#[inline(always)]
unsafe fn try_iter_links(ctx: *mut c_void) {
    let meta = *(ctx as *const *const *mut c_void);
    let link = *(ctx as *const u64).add(1);
    if link == 0 || meta.is_null() {
        return;
    }
    let seq = *meta;
    let (Some(o_type), Some(o_prog), Some(o_id)) = (
        off_opt!(BPF_LINK_TYPE_OFFSET),
        off_opt!(BPF_LINK_PROG_OFFSET),
        off_opt!(BPF_LINK_ID_OFFSET),
    ) else {
        return;
    };
    let Some(id) = rd_u32(link + o_id as u64) else {
        return;
    };
    let mut rec = LinkRecord {
        id,
        link_type: rd_u32(link + o_type as u64).unwrap_or(u32::MAX),
        prog_id: 0,
        _pad: 0,
    };
    if let Some(prog) = rd_u64(link + o_prog as u64) {
        if prog != 0 {
            if let Some(aux) = rd_u64(prog + off!(BPF_PROG_AUX_OFFSET) as u64) {
                if aux != 0 {
                    rec.prog_id =
                        rd_u32(aux + off!(BPF_PROG_AUX_ID_OFFSET) as u64).unwrap_or(0);
                }
            }
        }
    }
    bpf_seq_write(
        seq as *mut aya_ebpf::bindings::seq_file,
        &rec as *const LinkRecord as *const c_void,
        core::mem::size_of::<LinkRecord>() as u32,
    );
}
