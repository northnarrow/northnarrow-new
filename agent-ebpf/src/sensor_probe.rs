//! Tappa 10.9, step 0 — sensor-feasibility probes.
//!
//! Throw-away programs for the attach points proposed in
//! `docs/design/TAPPA10_9_SENSOR_ATTACH_POINTS_DESIGN.md`. They are loaded
//! only by `northnarrow-agent --sensor-feasibility`
//! (`agent/src/sensor_feasibility.rs`), never by the running agent, and only
//! look at the runner's own process (or, for exec, its children): the point
//! is whether each program loads under the verifier of every lab kernel and
//! reports what the design needs, not coverage.
//!
//! - `probe_file_open` (LSM `file_open`): parent-directory inode in
//!   [`PROBE_DIRS`]; leaf name (+ parent name) in [`PROBE_NAMES`]; ancestor
//!   name in [`PROBE_ANCESTORS`] (bounded walk); write-opens counted per tgid
//!   in [`PROBE_WRITES`] with one record per threshold crossing. One emit
//!   site, so the path walk is inlined once.
//! - `probe_bprm` (LSM `bprm_check_security`): the kernel copy of the
//!   filename and the resolved inode (superblock magic, `i_nlink`, `i_mode`).
//! - `probe_ip_make_skb` / `probe_ip6_make_skb` (kretprobe) and
//!   `probe_udp_send_skb` (kprobe, IPv4 and IPv6 symbols): the UDP payload
//!   read from the socket buffer after the kernel copied it.
//! - `probe_fexit_ip_make_skb` / `probe_fexit_ip6_make_skb`: empty fexit
//!   programs, loaded only to record whether this kernel's trampolines take
//!   functions of 10 and 9 arguments (x86-64 trampolines took at most 6
//!   before 6.5) — the RFC's Q5 proposed fexit there.
//!
//! The maps are small on purpose: the object is shared with the production
//! agent, which creates every map of the object at load time (about 70 KiB
//! for these until step 1 replaces the probes).
//!
//! Offsets of fields the production table does not have yet come from the
//! probes' own map [`PROBE_OFFSETS`], written by the runner from the live BTF.
use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task,
        bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel,
        bpf_probe_read_kernel_buf, bpf_probe_read_kernel_str_bytes,
    },
    macros::{fexit, kprobe, kretprobe, lsm, map},
    maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::{FExitContext, LsmContext, ProbeContext, RetProbeContext},
};
use northnarrow_common::wire::sensor_probe::{
    probe_slot, ProbeWriteWindow, SensorProbeRaw, PROBE_DETAIL_LEN, PROBE_KIND_ANCESTOR,
    PROBE_KIND_DIR, PROBE_KIND_DNS4, PROBE_KIND_DNS6, PROBE_KIND_EXEC, PROBE_KIND_MASS_WRITE,
    PROBE_KIND_NAME, PROBE_KIND_UDP_SEND_SKB, PROBE_MASS_WRITE_MIN, PROBE_MASS_WRITE_WINDOW_NS,
    PROBE_OFFSETS_MAGIC, PROBE_PATH_SLOTS, PROBE_PATH_SLOT_LEN,
};
use northnarrow_common::wire::InodeKey;

use crate::btf_offsets::{
    DENTRY_D_INODE_OFFSET, DENTRY_D_NAME_OFFSET, DENTRY_D_PARENT_OFFSET, FILE_F_INODE_OFFSET,
    FILE_F_MODE_OFFSET, FILE_F_PATH_OFFSET, INODE_I_INO_OFFSET, INODE_I_SB_OFFSET,
    PATH_DENTRY_OFFSET, QSTR_NAME_OFFSET, SUPER_BLOCK_S_DEV_OFFSET, TASK_STRUCT_REAL_PARENT_OFFSET,
    TASK_STRUCT_TGID_OFFSET,
};

const NAME_LEN: usize = 32;
const FMODE_WRITE: u32 = 0x2;
const ANCESTOR_DEPTH: usize = 8;
/// UDP header length: the payload starts this far after `transport_header`.
const UDP_HDR_LEN: usize = 8;
/// Bytes of UDP payload copied (DNS header + a QNAME of the test's size).
const PAYLOAD_COPY: usize = 96;

#[map]
static PROBE_OFFSETS: Array<u32> = Array::with_max_entries(probe_slot::COUNT, 0);
/// Slot 0: the runner's tgid (0 = probes disarmed).
#[map]
static PROBE_TARGET: Array<u32> = Array::with_max_entries(1, 0);
#[map]
static PROBE_DIRS: HashMap<InodeKey, u8> = HashMap::with_max_entries(16, 0);
/// Key: leaf name (32 bytes) ‖ parent name (32 bytes, all zero = any parent).
#[map]
static PROBE_NAMES: HashMap<[u8; 64], u8> = HashMap::with_max_entries(16, 0);
#[map]
static PROBE_ANCESTORS: HashMap<[u8; NAME_LEN], u8> = HashMap::with_max_entries(16, 0);
/// Only the runner's tgid is counted; LRU so the shape is step 1's.
#[map]
static PROBE_WRITES: LruHashMap<u32, ProbeWriteWindow> = LruHashMap::with_max_entries(16, 0);
/// Name keys are built in map memory, never on the stack (5.15 rule 4).
#[map]
static PROBE_SCRATCH: PerCpuArray<[u8; 64]> = PerCpuArray::with_max_entries(1, 0);
/// 64 KiB: about 90 records; the runner drains after every exercise.
#[map]
pub static PROBE_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

/// Offset of a field the production `BTF_OFFSETS` table does not carry;
/// `None` when the runner did not arm the map or the field is absent.
#[inline(always)]
fn poff(slot: u32) -> Option<usize> {
    match PROBE_OFFSETS.get(probe_slot::MAGIC) {
        Some(m) if *m == PROBE_OFFSETS_MAGIC => match PROBE_OFFSETS.get(slot) {
            Some(v) if *v != u32::MAX => Some(*v as usize),
            _ => None,
        },
        _ => None,
    }
}

#[inline(always)]
fn target() -> u32 {
    match PROBE_TARGET.get(0) {
        Some(t) => *t,
        None => 0,
    }
}

#[inline(always)]
fn current_is_target() -> bool {
    let t = target();
    t != 0 && (bpf_get_current_pid_tgid() >> 32) as u32 == t
}

#[inline(always)]
unsafe fn read_ptr(p: *const u8) -> *const u8 {
    match bpf_probe_read_kernel::<*const u8>(p as *const *const u8) {
        Ok(v) => v,
        Err(_) => core::ptr::null(),
    }
}

#[inline(always)]
unsafe fn inode_key(inode: *const u8) -> InodeKey {
    let mut key = InodeKey { dev: 0, ino: 0 };
    if inode.is_null() {
        return key;
    }
    let sb = read_ptr(inode.add(off!(INODE_I_SB_OFFSET)));
    if !sb.is_null() {
        if let Ok(dev) = bpf_probe_read_kernel::<u32>(sb.add(off!(SUPER_BLOCK_S_DEV_OFFSET)) as *const u32) {
            key.dev = dev as u64;
        }
    }
    if let Ok(ino) = bpf_probe_read_kernel::<u64>(inode.add(off!(INODE_I_INO_OFFSET)) as *const u64) {
        key.ino = ino;
    }
    key
}

/// Read `dentry->d_name.name` (NUL-padded) into `dst[..32]`.
#[inline(always)]
unsafe fn read_name(dentry: *const u8, dst: *mut u8) {
    let w = dst as *mut u64;
    core::ptr::write_volatile(w, 0);
    core::ptr::write_volatile(w.add(1), 0);
    core::ptr::write_volatile(w.add(2), 0);
    core::ptr::write_volatile(w.add(3), 0);
    if dentry.is_null() {
        return;
    }
    let name = read_ptr(dentry.add(off!(DENTRY_D_NAME_OFFSET) + off!(QSTR_NAME_OFFSET)));
    if !name.is_null() {
        let slot = core::slice::from_raw_parts_mut(dst, NAME_LEN);
        let _ = bpf_probe_read_kernel_str_bytes(name, slot);
    }
}

#[lsm(hook = "file_open")]
pub fn probe_file_open(ctx: LsmContext) -> i32 {
    unsafe { try_probe_file_open(&ctx) };
    0
}

#[inline(always)]
unsafe fn try_probe_file_open(ctx: &LsmContext) {
    if !current_is_target() {
        return;
    }
    let file: *const u8 = ctx.arg(0);
    if file.is_null() {
        return;
    }
    let inode = read_ptr(file.add(off!(FILE_F_INODE_OFFSET)));
    let dentry = read_ptr(file.add(off!(FILE_F_PATH_OFFSET) + off!(PATH_DENTRY_OFFSET)));
    if inode.is_null() || dentry.is_null() {
        return;
    }
    let f_mode = match bpf_probe_read_kernel::<u32>(file.add(off!(FILE_F_MODE_OFFSET)) as *const u32) {
        Ok(m) => m,
        Err(_) => 0,
    };
    let mut kind: u8 = 0;
    if f_mode & FMODE_WRITE != 0 && count_write() {
        kind = PROBE_KIND_MASS_WRITE;
    }
    let parent = read_ptr(dentry.add(off!(DENTRY_D_PARENT_OFFSET)));
    if kind == 0 && !parent.is_null() {
        let pkey = inode_key(read_ptr(parent.add(off!(DENTRY_D_INODE_OFFSET))));
        if PROBE_DIRS.get(&pkey).is_some() {
            kind = PROBE_KIND_DIR;
        }
    }
    let scratch = match PROBE_SCRATCH.get_ptr_mut(0) {
        Some(p) => p as *mut u8,
        None => return,
    };
    if kind == 0 {
        read_name(dentry, scratch);
        read_name(parent, scratch.add(NAME_LEN));
        if PROBE_NAMES.get(&*(scratch as *const [u8; 64])).is_some() {
            kind = PROBE_KIND_NAME;
        } else {
            read_name(core::ptr::null(), scratch.add(NAME_LEN));
            if PROBE_NAMES.get(&*(scratch as *const [u8; 64])).is_some() {
                kind = PROBE_KIND_NAME;
            }
        }
    }
    if kind == 0 {
        let mut d = parent;
        for _ in 0..ANCESTOR_DEPTH {
            if d.is_null() {
                break;
            }
            read_name(d, scratch);
            if PROBE_ANCESTORS.get(&*(scratch as *const [u8; NAME_LEN])).is_some() {
                kind = PROBE_KIND_ANCESTOR;
                break;
            }
            let up = read_ptr(d.add(off!(DENTRY_D_PARENT_OFFSET)));
            if up == d {
                break;
            }
            d = up;
        }
    }
    if kind != 0 {
        emit(kind, inode, dentry, f_mode, core::ptr::null(), 0);
    }
}

/// Per-tgid write-open window; `true` exactly once per crossing of
/// [`PROBE_MASS_WRITE_MIN`] within [`PROBE_MASS_WRITE_WINDOW_NS`].
#[inline(always)]
unsafe fn count_write() -> bool {
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = bpf_ktime_get_ns();
    match PROBE_WRITES.get_ptr_mut(&tgid) {
        Some(w) => {
            if now.saturating_sub((*w).start_ns) > PROBE_MASS_WRITE_WINDOW_NS {
                (*w).start_ns = now;
                (*w).count = 1;
                (*w).fired = 0;
                false
            } else {
                (*w).count += 1;
                if (*w).count >= PROBE_MASS_WRITE_MIN && (*w).fired == 0 {
                    (*w).fired = 1;
                    true
                } else {
                    false
                }
            }
        }
        None => {
            let w = ProbeWriteWindow {
                start_ns: now,
                count: 1,
                fired: 0,
            };
            let _ = PROBE_WRITES.insert(&tgid, &w, 0);
            false
        }
    }
}

#[lsm(hook = "bprm_check_security")]
pub fn probe_bprm(ctx: LsmContext) -> i32 {
    unsafe { try_probe_bprm(&ctx) };
    0
}

/// `true` when the current task's real parent is the runner.
#[inline(always)]
unsafe fn parent_is_target() -> bool {
    let t = target();
    if t == 0 {
        return false;
    }
    let task = bpf_get_current_task() as *const u8;
    if task.is_null() {
        return false;
    }
    let parent = read_ptr(task.add(off!(TASK_STRUCT_REAL_PARENT_OFFSET)));
    if parent.is_null() {
        return false;
    }
    match bpf_probe_read_kernel::<u32>(parent.add(off!(TASK_STRUCT_TGID_OFFSET)) as *const u32) {
        Ok(tgid) => tgid == t,
        Err(_) => false,
    }
}

#[inline(always)]
unsafe fn try_probe_bprm(ctx: &LsmContext) {
    if !parent_is_target() {
        return;
    }
    let bprm: *const u8 = ctx.arg(0);
    if bprm.is_null() {
        return;
    }
    let (file_off, name_off) = match (poff(probe_slot::LINUX_BINPRM_FILE), poff(probe_slot::LINUX_BINPRM_FILENAME)) {
        (Some(a), Some(b)) => (a, b),
        _ => return,
    };
    let file = read_ptr(bprm.add(file_off));
    if file.is_null() {
        return;
    }
    let inode = read_ptr(file.add(off!(FILE_F_INODE_OFFSET)));
    let dentry = read_ptr(file.add(off!(FILE_F_PATH_OFFSET) + off!(PATH_DENTRY_OFFSET)));
    let filename = read_ptr(bprm.add(name_off));
    emit(PROBE_KIND_EXEC, inode, dentry, 0, filename, 0);
}

#[kretprobe]
pub fn probe_ip_make_skb(ctx: RetProbeContext) -> u32 {
    unsafe { probe_skb_ret(&ctx, PROBE_KIND_DNS4) };
    0
}

#[kretprobe]
pub fn probe_ip6_make_skb(ctx: RetProbeContext) -> u32 {
    unsafe { probe_skb_ret(&ctx, PROBE_KIND_DNS6) };
    0
}

#[kprobe]
pub fn probe_udp_send_skb(ctx: ProbeContext) -> u32 {
    unsafe {
        if current_is_target() {
            let skb: *const u8 = match ctx.arg(0) {
                Some(p) => p,
                None => return 0,
            };
            emit_skb(skb, PROBE_KIND_UDP_SEND_SKB);
        }
    }
    0
}

#[fexit(function = "ip_make_skb")]
pub fn probe_fexit_ip_make_skb(_ctx: FExitContext) -> u32 {
    0
}

#[fexit(function = "ip6_make_skb")]
pub fn probe_fexit_ip6_make_skb(_ctx: FExitContext) -> u32 {
    0
}

#[inline(always)]
unsafe fn probe_skb_ret(ctx: &RetProbeContext, kind: u8) {
    if !current_is_target() {
        return;
    }
    let skb: *const u8 = match ctx.ret() {
        Some(p) => p,
        None => return,
    };
    // ERR_PTR() values sit in the last page of the address space.
    if skb.is_null() || (skb as u64) >= 0xffff_ffff_ffff_f000 {
        return;
    }
    emit_skb(skb, kind);
}

#[inline(always)]
unsafe fn emit_skb(skb: *const u8, kind: u8) {
    let (head_off, th_off, len_off) = match (
        poff(probe_slot::SK_BUFF_HEAD),
        poff(probe_slot::SK_BUFF_TRANSPORT_HEADER),
        poff(probe_slot::SK_BUFF_LEN),
    ) {
        (Some(a), Some(b), Some(c)) => (a, b, c),
        _ => return,
    };
    let head = read_ptr(skb.add(head_off));
    let th = match bpf_probe_read_kernel::<u16>(skb.add(th_off) as *const u16) {
        Ok(v) => v as usize,
        Err(_) => return,
    };
    let len = match bpf_probe_read_kernel::<u32>(skb.add(len_off) as *const u32) {
        Ok(v) => v,
        Err(_) => 0,
    };
    if head.is_null() || th == 0xffff {
        return;
    }
    let payload = head.add((th & 0xffff) + UDP_HDR_LEN);
    emit(kind, core::ptr::null(), core::ptr::null(), len, payload, skb as u64);
}

/// The one emit site per program. `inode`/`dentry` fill the identity and
/// the path; `detail_src` is a kernel string (exec filename, `aux == 0`) or
/// a UDP payload (`aux` = skb pointer, fixed-size read).
#[inline(always)]
unsafe fn emit(kind: u8, inode: *const u8, dentry: *const u8, mode: u32, detail_src: *const u8, aux: u64) {
    let mut entry = match PROBE_EVENTS.reserve::<SensorProbeRaw>(0) {
        Some(e) => e,
        None => return,
    };
    let raw: *mut SensorProbeRaw = entry.as_mut_ptr();
    crate::zero::zero(raw);
    (*raw).timestamp_ns = bpf_ktime_get_ns();
    (*raw).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    (*raw).uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;
    if let Ok(comm) = bpf_get_current_comm() {
        (*raw).comm = comm;
    }
    (*raw).kind = kind;
    (*raw).mode = mode;
    (*raw).aux = aux;
    if !inode.is_null() {
        let key = inode_key(inode);
        (*raw).dev = key.dev;
        (*raw).ino = key.ino;
        if let Some(o) = poff(probe_slot::INODE_I_NLINK) {
            if let Ok(n) = bpf_probe_read_kernel::<u32>(inode.add(o) as *const u32) {
                (*raw).nlink = n;
            }
        }
        if kind == PROBE_KIND_EXEC {
            if let Some(o) = poff(probe_slot::INODE_I_MODE) {
                if let Ok(m) = bpf_probe_read_kernel::<u16>(inode.add(o) as *const u16) {
                    (*raw).mode = m as u32;
                }
            }
        }
        if let Some(o) = poff(probe_slot::SUPER_BLOCK_S_MAGIC) {
            let sb = read_ptr(inode.add(off!(INODE_I_SB_OFFSET)));
            if !sb.is_null() {
                if let Ok(m) = bpf_probe_read_kernel::<u64>(sb.add(o) as *const u64) {
                    (*raw).s_magic = m;
                }
            }
        }
    }
    if !dentry.is_null() {
        let (n, truncated) = walk_path(dentry, (*raw).path.as_mut_ptr());
        (*raw).path_n = n as u16;
        (*raw).path_truncated = truncated as u8;
    }
    if !detail_src.is_null() {
        let dst = core::slice::from_raw_parts_mut((*raw).detail.as_mut_ptr(), PROBE_DETAIL_LEN);
        if aux == 0 {
            if let Ok(s) = bpf_probe_read_kernel_str_bytes(detail_src, dst) {
                (*raw).detail_len = s.len() as u16;
            }
        } else {
            let part = core::slice::from_raw_parts_mut((*raw).detail.as_mut_ptr(), PAYLOAD_COPY);
            if bpf_probe_read_kernel_buf(detail_src, part).is_ok() {
                (*raw).detail_len = PAYLOAD_COPY as u16;
            }
        }
    }
    entry.submit(0);
}

/// `module_load.rs`'s fixed-slot walk: each component leaf → root into a
/// constant 32-byte slot; `(slots, truncated)`.
#[inline(always)]
unsafe fn walk_path(leaf: *const u8, dst: *mut u8) -> (usize, bool) {
    let mut dentry = leaf;
    let mut n: usize = 0;
    let mut reached_root = false;
    for i in 0..PROBE_PATH_SLOTS {
        if dentry.is_null() {
            break;
        }
        let off = i * PROBE_PATH_SLOT_LEN;
        let name = read_ptr(dentry.add(off!(DENTRY_D_NAME_OFFSET) + off!(QSTR_NAME_OFFSET)));
        if !name.is_null() {
            let slot = core::slice::from_raw_parts_mut(dst.add(off), PROBE_PATH_SLOT_LEN);
            let _ = bpf_probe_read_kernel_str_bytes(name, slot);
        }
        n = i + 1;
        let up = read_ptr(dentry.add(off!(DENTRY_D_PARENT_OFFSET)));
        if up == dentry {
            reached_root = true;
            break;
        }
        dentry = up;
    }
    (n, !reached_root)
}
