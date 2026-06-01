//! Module-load BPF-LSM hooks (BUG-034) — kernel-module / rootkit-LKM
//! detection at the load chokepoint.
//!
//! Two BPF-LSM programs OBSERVE (never deny, this commit) the two
//! kernel module-load paths:
//!
//! | Hook | Syscall | What it gives |
//! |---|---|---|
//! | `kernel_read_file` (id = READING_MODULE) | `finit_module(2)` (modern) | `struct file*` → **source path** + loader |
//! | `kernel_load_data` (id = LOADING_MODULE) | `init_module(2)` (legacy buffer) | loader only (no file, no path) |
//!
//! Why a load hook, not more file-watching: FIM-008 watches a `.ko`
//! appearing on disk (evaded by a `/tmp` drop) and R011 watches the
//! insmod/modprobe *exec* (evaded by a direct `finit_module(2)`). The
//! LOAD itself is the one chokepoint a rootkit cannot avoid. Each load
//! emits one [`ModuleLoadRaw`] on [`MODULE_LOAD_EVENTS`].
//!
//! STAGE 1b (this commit): the `kernel_read_file` hook resolves the
//! source `.ko` path via a bounded `d_parent` walk, and both hooks
//! capture the loader's `parent_is_kthread` (the non-forgeable R011
//! exemption signal) + `parent_comm`. The userland rule (stage 2)
//! consumes the ring; a temporary log-drain in the multiplexer surfaces
//! the resolved path for this commit's VM verification.
//!
//! ## Path capture (verifier-friendly fixed-slot scheme)
//!
//! `bpf_d_path` is avoided: it needs a BTF-typed `struct path*` arg and
//! `security_kernel_read_file` may not be on the kernel's
//! `btf_allowlist_d_path` — two ways to fail. Instead we walk
//! `file → f_path.dentry` up the `d_parent` chain on RAW pointers via
//! `bpf_probe_read_kernel` (no allowlist, no BTF-id requirement), writing
//! each component leaf→root into a FIXED 32-byte slot of `path`
//! (`MODULE_PATH_SLOTS` × `MODULE_PATH_SLOT_LEN` = 256). Fixed slot
//! offsets keep the verifier's bounds-tracking trivial — no running
//! offset. `path_len` carries the slot COUNT; userland reverses the
//! slots to rebuild the path (`/lib/modules/<rel>` legit vs `/tmp` etc.).

use aya_ebpf::{
    cty::{c_int, c_void},
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task,
        bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel,
        bpf_probe_read_kernel_str_bytes,
    },
    macros::{lsm, map},
    maps::RingBuf,
    programs::LsmContext,
};

use northnarrow_common::wire::{ModuleLoadRaw, MODULE_LOAD_FINIT, MODULE_LOAD_INIT};

use crate::btf_offsets::{
    DENTRY_D_NAME_OFFSET, DENTRY_D_PARENT_OFFSET, FILE_F_PATH_OFFSET, PATH_DENTRY_OFFSET,
    PF_KTHREAD, QSTR_NAME_OFFSET, TASK_STRUCT_COMM_OFFSET, TASK_STRUCT_FLAGS_OFFSET,
    TASK_STRUCT_REAL_PARENT_OFFSET,
};

/// `enum kernel_read_file_id::READING_MODULE` (vmlinux BTF, 6.8).
const READING_MODULE: c_int = 2;
/// `enum kernel_load_data_id::LOADING_MODULE` (vmlinux BTF, 6.8).
const LOADING_MODULE: c_int = 2;

/// Path captured as up to 8 leaf→root components, each in a fixed
/// 32-byte slot of `ModuleLoadRaw.path` (8 × 32 = 256 = MODULE_PATH_LEN).
const MODULE_PATH_SLOTS: usize = 8;
const MODULE_PATH_SLOT_LEN: usize = 32;

/// Kernel `comm` length — `ModuleLoadRaw.parent_comm` is `[u8; 16]`.
const COMM_LEN: usize = 16;

/// Module-load observations (see file-level docs for the no-pin /
/// reattach-fresh rationale). 64 KiB ≈ ~200 [`ModuleLoadRaw`] (312 B).
#[map]
pub static MODULE_LOAD_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

#[lsm(hook = "kernel_read_file")]
pub fn module_read_file_observe(ctx: LsmContext) -> i32 {
    unsafe { try_read_file(&ctx) }
}

#[inline(always)]
unsafe fn try_read_file(ctx: &LsmContext) -> i32 {
    // kernel_read_file(struct file *file, enum kernel_read_file_id id, bool contents)
    let id: c_int = ctx.arg(1);
    if id != READING_MODULE {
        return 0;
    }
    let file: *const c_void = ctx.arg(0);
    emit_module_load(MODULE_LOAD_FINIT, file);
    0
}

#[lsm(hook = "kernel_load_data")]
pub fn module_load_data_observe(ctx: LsmContext) -> i32 {
    unsafe { try_load_data(&ctx) }
}

#[inline(always)]
unsafe fn try_load_data(ctx: &LsmContext) -> i32 {
    // kernel_load_data(enum kernel_load_data_id id, bool contents)
    let id: c_int = ctx.arg(0);
    if id != LOADING_MODULE {
        return 0;
    }
    // Legacy init_module buffer load — no file, so no path. Its mere
    // firing is the signal (legacy interface is rarely used legitimately).
    emit_module_load(MODULE_LOAD_INIT, core::ptr::null());
    0
}

/// Best-effort observation record. Drops silently if the ring is full
/// (the load still proceeds — detection, not enforcement).
#[inline(always)]
unsafe fn emit_module_load(method: u8, file: *const c_void) {
    let mut entry = match MODULE_LOAD_EVENTS.reserve::<ModuleLoadRaw>(0) {
        Some(e) => e,
        None => return,
    };
    let raw: *mut ModuleLoadRaw = entry.as_mut_ptr();
    // Zero the whole slot first so `_pad` + any unwritten path slots
    // stay deterministic (a `bytemuck::Pod` requirement userland-side).
    core::ptr::write_bytes(raw, 0u8, 1);
    (*raw).timestamp_ns = bpf_ktime_get_ns();
    (*raw).loader_pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    (*raw).loader_uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;
    (*raw).method = method;
    if let Ok(comm) = bpf_get_current_comm() {
        (*raw).loader_comm = comm;
    }
    fill_parent(raw);
    if method == MODULE_LOAD_FINIT && !file.is_null() {
        // file → f_path.dentry (the source .ko's leaf dentry).
        let dentry_slot =
            (file as *const u8).add(FILE_F_PATH_OFFSET + PATH_DENTRY_OFFSET) as *const *const u8;
        if let Ok(leaf) = bpf_probe_read_kernel::<*const u8>(dentry_slot) {
            if !leaf.is_null() {
                (*raw).path_len = walk_components(leaf, (*raw).path.as_mut_ptr()) as u16;
            }
        }
    }
    entry.submit(0);
}

/// Walk the `d_parent` chain from `leaf`, writing each component name
/// leaf→root into a FIXED 32-byte slot of `dst`. The slot offset comes
/// from a `match` on the iteration index → a constant per iteration, so
/// the verifier sees in-bounds writes into the 256-byte `path` field
/// with no running-offset reasoning. Returns the slot count written;
/// userland reverses the slots to rebuild the path. Fails SAFE — any
/// failed probe stops the walk (short/empty path, never garbage).
#[inline(always)]
unsafe fn walk_components(leaf: *const u8, dst: *mut u8) -> usize {
    let mut dentry = leaf;
    let mut n: usize = 0;
    for i in 0..MODULE_PATH_SLOTS {
        if dentry.is_null() {
            break;
        }
        let off = match i {
            0 => 0,
            1 => 32,
            2 => 64,
            3 => 96,
            4 => 128,
            5 => 160,
            6 => 192,
            7 => 224,
            _ => break,
        };
        // dentry->d_name.name (struct qstr → const u8*).
        let name_pp =
            dentry.add(DENTRY_D_NAME_OFFSET + QSTR_NAME_OFFSET) as *const *const u8;
        if let Ok(name_ptr) = bpf_probe_read_kernel::<*const u8>(name_pp) {
            if !name_ptr.is_null() {
                let slot = core::slice::from_raw_parts_mut(dst.add(off), MODULE_PATH_SLOT_LEN);
                let _ = bpf_probe_read_kernel_str_bytes(name_ptr, slot);
            }
        }
        n = i + 1;
        // Step to the parent; stop at the root (d_parent == self) or a
        // failed/null read.
        match bpf_probe_read_kernel::<*const u8>(dentry.add(DENTRY_D_PARENT_OFFSET) as *const *const u8) {
            Ok(p) if !p.is_null() && p != dentry => dentry = p,
            _ => break,
        }
    }
    n
}

/// Read the loader's real-parent `comm` + `PF_KTHREAD` flag into `raw`.
/// PF_KTHREAD is non-forgeable from userspace (kernel-set on kthread
/// creation) — the same R011 exemption signal for kernel-driven boot
/// hardware-probe loads. Fails SAFE: a failed probe leaves
/// `parent_is_kthread = 0`, which the rule treats as "userspace parent"
/// (fire path), never a silent exemption.
#[inline(always)]
unsafe fn fill_parent(raw: *mut ModuleLoadRaw) {
    let task = bpf_get_current_task() as *const u8;
    if task.is_null() {
        return;
    }
    let parent = match bpf_probe_read_kernel::<*const u8>(
        task.add(TASK_STRUCT_REAL_PARENT_OFFSET) as *const *const u8,
    ) {
        Ok(p) if !p.is_null() => p,
        _ => return,
    };
    let comm_slot = core::slice::from_raw_parts_mut((*raw).parent_comm.as_mut_ptr(), COMM_LEN);
    let _ = bpf_probe_read_kernel_str_bytes(parent.add(TASK_STRUCT_COMM_OFFSET), comm_slot);
    if let Ok(flags) =
        bpf_probe_read_kernel::<u32>(parent.add(TASK_STRUCT_FLAGS_OFFSET) as *const u32)
    {
        if flags & PF_KTHREAD != 0 {
            (*raw).parent_is_kthread = 1;
        }
    }
}
