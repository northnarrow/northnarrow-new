//! Tappa 10.9 step 1 — the file-open sensor on LSM `file_open`.
//!
//! Design: `docs/design/TAPPA10_9_SENSOR_ATTACH_POINTS_DESIGN.md` §10.
//! [`observe`] runs inside the sensor variant of the FIM `file_open`
//! observer (`fim_watch::fim_file_open_sensor`, [`on_open`]), which has
//! already computed the open's inode key: one program per open, one key. Instead of shipping
//! every `openat` from `sys_enter_openat`, it ships only the opens a
//! consumer reads, plus one record per mass-write burst:
//!
//! - rules on the file itself ([`OPEN_RULES`]): sensitive, critical and
//!   persistence files;
//! - the class of the parent directory, cached in [`DIR_CLASS`]: critical
//!   and persistence trees, the telemetry probe directory, credential
//!   stores, home trees, mass-write carve-outs and runtime directories.
//!   A miss walks at most [`OPEN_CLASSIFY_DEPTH`] ancestors through
//!   [`OPEN_RULES`], [`CHILD_RULES`] and [`OPEN_NAME_RULES`];
//! - the leaf name, read only when the class says leaves matter;
//! - write-opens counted per tgid ([`OPEN_WRITES`]), and the rewrites of
//!   existing files also per cgroup ([`OPEN_CG_WRITES`]), in the global
//!   function [`nn_open_count_write`]. Lot 282: a file rewritten counts
//!   once per window ([`OPEN_OVERWRITE_SEEN`]), files created are counted
//!   apart, and the originals destroyed (unlinked, or replaced by a rename
//!   onto their name) count once per name ([`OPEN_DESTROY_SEEN`]).
//!
//! [`DIR_CLASS_GEN`] invalidates the cache: directory renames
//! (`fim_rename_observe`) and rule changes by userland bump it; `rmdir`
//! ([`open_sensor_rmdir`]) drops the removed directory's entry. Nothing
//! runs until userland arms [`OPEN_SENSOR`]
//! (LSM mode); with the configuration switch on "tracepoint" the agent
//! keeps `sys_enter_openat` and leaves this off.
use aya_ebpf::{
    cty::c_void,
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_pid_tgid,
        bpf_get_current_task, bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel,
        bpf_probe_read_kernel_buf, bpf_probe_read_kernel_str_bytes, generated,
    },
    macros::{lsm, map},
    maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::LsmContext,
    EbpfContext,
};
use northnarrow_common::wire::open_sensor::{
    open_class::{
        CHILDREN_PROBE, CHILD_FILES, CLASSIFIED, DEPTH_CAPPED, DIRECT, DIR_HAS_FILES,
        FILE_CRITICAL, FILE_PERSIST, FILE_SENSITIVE, LEAF_CRED, LEAVES_CRED, OWN_DATA_BITS, SUBTREE,
        TREE_CARVEOUT, TREE_CRED, TREE_CRITICAL, TREE_HOME, TREE_PERSIST, TREE_RUNTIME,
        TREE_USER_CACHE,
    },
    carved_class, cgroup_step, created_in_window, destroys_an_original, first_in_window,
    first_write, kdbx_suffix, marks_had_data, name_ext, open_reason, own_after, own_code, rename_shape_with, rename_step, unlink_step, write_kind, write_step, ChildRuleKey,
    DestroySeenKey, DirClass, NameParts, OpenCgKey, OpenCgWindow, OpenRecordRaw, OpenWriteWindow,
    OverwriteSeenKey, RenameNames, RenameWindow, UnlinkWindow, WriteKind, CHILD_RULES_MAX, NAME_HEAD_LEN,
    NAME_TAIL_LEN, OPEN_CLASSIFY_DEPTH, OPEN_NAME_LEN, OPEN_NAME_RULES_MAX, OPEN_PATH_SLOTS,
    OPEN_PATH_SLOT_LEN, OPEN_RULES_MAX, OPEN_SENSOR_ARMED, OVERWRITE_MIN_BYTES, RENAME_APPENDED,
    RENAME_OTHER, RUNTIME_UIDS_MAX,
};
use northnarrow_common::wire::{InodeKey, FIM_OP_OPENED};

use crate::btf_offsets::{
    DENTRY_D_INODE_OFFSET, DENTRY_D_NAME_OFFSET, DENTRY_D_PARENT_OFFSET, FILE_F_FLAGS_OFFSET,
    FILE_F_INODE_OFFSET, FILE_F_MODE_OFFSET, FILE_F_PATH_OFFSET, INODE_I_INO_OFFSET, INODE_I_MODE_OFFSET,
    INODE_I_SIZE_OFFSET,
    INODE_I_NLINK_OFFSET, INODE_I_SB_OFFSET, INODE_I_UID_OFFSET, PATH_DENTRY_OFFSET, QSTR_LEN_OFFSET,
    QSTR_NAME_OFFSET, SUPER_BLOCK_S_DEV_OFFSET,
    SUPER_BLOCK_S_MAGIC_OFFSET, TASK_STRUCT_LOGINUID_OFFSET,
};
use crate::read_repeat::ReadSeenKey;

const FMODE_WRITE: u32 = 0x2;
/// `FMODE_CREATED` (include/linux/fs.h, `1 << 20` since 4.19): this open
/// created the file. Set before `security_file_open` runs.
const FMODE_CREATED: u32 = 0x10_0000;

/// `BTRFS_SUPER_MAGIC`, include/uapi/linux/magic.h.
const BTRFS_SUPER_MAGIC: u64 = 0x9123_683E;
const S_IFMT: u16 = 0o170_000;
const S_IFREG: u16 = 0o100_000;
const S_IFDIR: u16 = 0o040_000;

/// Filesystems whose writes are kernel calls, not data (the posture's
/// old `/sys/` and `/proc/` prefixes, and what is mounted under `/sys`).
const CARVEOUT_MAGICS: [u64; 11] = [
    0x6265_6572, // sysfs
    0x9fa0,      // procfs
    0x0027_e0eb, // cgroup
    0x6367_7270, // cgroup2
    0xcafe_4a11, // bpffs
    0x6462_6720, // debugfs
    0x7472_6163, // tracefs
    0x7363_6673, // securityfs
    0x6265_6570, // configfs
    0x6165_676c, // pstore
    0xde5e_81e4, // efivarfs
];

/// Slot 0: [`OPEN_SENSOR_ARMED`] in LSM mode, anything else = off.
#[map]
pub static OPEN_SENSOR: Array<u32> = Array::with_max_entries(1, 0);
/// Inode rules: a file's own class, or a directory's class for its
/// children / subtree (`open_class`).
#[map]
pub static OPEN_RULES: HashMap<InodeKey, u32> = HashMap::with_max_entries(OPEN_RULES_MAX, 0);
/// `(registered directory, child name)` rules for paths missing when
/// userland registered the rules.
#[map]
pub static CHILD_RULES: HashMap<ChildRuleKey, u32> = HashMap::with_max_entries(CHILD_RULES_MAX, 0);
/// Name rules, key = name ‖ parent name (all-zero parent = any parent):
/// directory names (`TREE_CRED`, `LEAVES_CRED`) and leaf names
/// (`LEAF_CRED`).
#[map]
pub static OPEN_NAME_RULES: HashMap<[u8; 2 * OPEN_NAME_LEN], u32> =
    HashMap::with_max_entries(OPEN_NAME_RULES_MAX, 0);
/// Owner uid of each registered runtime directory (`TREE_RUNTIME`).
#[map]
pub static RUNTIME_UIDS: HashMap<InodeKey, u32> = HashMap::with_max_entries(RUNTIME_UIDS_MAX, 0);
/// Directory class cache, keyed by the directory's inode.
#[map]
pub static DIR_CLASS: LruHashMap<InodeKey, DirClass> = LruHashMap::with_max_entries(16384, 0);
/// External audit EBPF-011: directory classifications whose walk stopped
/// at [`OPEN_CLASSIFY_DEPTH`] before the filesystem root (slot 0, per CPU).
/// Counted in [`nn_open_walk`], read by userland.
#[map]
pub static OPEN_DEPTH_CAPPED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
/// Slot 0: the cache generation; a [`DirClass`] of another one is stale.
#[map]
pub static DIR_CLASS_GEN: Array<u32> = Array::with_max_entries(1, 0);
/// Per-tgid write-open windows (mass write).
#[map]
static OPEN_WRITES: LruHashMap<u32, OpenWriteWindow> = LruHashMap::with_max_entries(4096, 0);
/// External audit EBPF-011: per-cgroup overwrite windows (a writer that
/// forks a fresh worker every few files stays under the per-tgid one).
#[map]
static OPEN_CG_WRITES: LruHashMap<OpenCgKey, OpenCgWindow> = LruHashMap::with_max_entries(1024, 0);
/// Lot 282: the files each tgid wrote in its current write window (the
/// value: that window's start). A file's later opens in the window are
/// plain write-opens, not rewrites of another file: one database rewritten
/// 259 times was a mass overwrite. The review of #500 (B1): every file
/// written, so a file written new counts once too, whatever made it. An
/// evicted entry counts its file again.
#[map]
static OPEN_OVERWRITE_SEEN: LruHashMap<OverwriteSeenKey, u64> = LruHashMap::with_max_entries(16384, 0);
/// Lot 282: the originals each tgid destroyed in its current unlink window,
/// by name (the value: that window's start). A name destroyed again (a
/// journal at every commit, a lock file) is one original.
#[map]
static OPEN_DESTROY_SEEN: LruHashMap<DestroySeenKey, u64> = LruHashMap::with_max_entries(16384, 0);
/// Lot 282: the files each tgid created (the value: when), so that its own
/// temporary files, unlinked or renamed over, are no originals destroyed
/// (`pip` and `npm` unpack into files they delete). An evicted entry makes
/// such a file count as an original — more, never fewer.
#[map]
static OPEN_CREATED: LruHashMap<OverwriteSeenKey, u64> = LruHashMap::with_max_entries(16384, 0);
/// Lot 282, the review of #500 (C1): the regular files seen holding data
/// at an `inode_setattr` (a chmod, a chown, a `touch`, a truncate — whose
/// own setattr runs before it empties the file), by inode (the value:
/// when), so that one emptied by a truncate and then unlinked is an
/// original destroyed ([`destroys_an_original`]), whoever unlinks it. An
/// evicted entry makes such an unlink count nothing — as it counted before.
#[map]
static OPEN_HAD_DATA: LruHashMap<InodeKey, u64> = LruHashMap::with_max_entries(4096, 0);
/// Review 75: the last read-only report per (task, inode)
/// ([`crate::read_repeat`]).
#[map]
static OPEN_READ_SEEN: LruHashMap<ReadSeenKey, u64> = LruHashMap::with_max_entries(8192, 0);
/// Bulk windows, each read in one call: `struct file` at [0, FILE_WIN) and
/// the opened inode at [FILE_WIN, FILE_WIN + INODE_WIN). A kernel read
/// costs about 70 ns on the lab; one window replaces four field reads
/// (design §9.1).
const FILE_WIN: usize = 256;
const INODE_WIN: usize = 128;
/// The sensor's buffers for one run: the windows, then the names and the
/// child-rule key, built here, never on the stack ([0..32) a name, [32..64)
/// its parent's name, [64..112) a `ChildRuleKey`; 5.15 rule 4).
#[repr(C)]
pub(crate) struct OpenTask {
    win: [u8; FILE_WIN + INODE_WIN],
    names: [u8; 128],
}
/// Lot 322 (the review of #546, F3): [`OpenTask`] is the running task's own
/// entry, keyed by its `task_struct` (`crate::task_scratch`), made by
/// [`on_open`] (or by the walk, from `inode_unlink` / `inode_rename`) and
/// removed before the program returns. They were two per-CPU buffers in
/// programs that run preemptible: on a `full`/`lazy` kernel another task's
/// open on the same CPU could rewrite the window or the names between the
/// read and the use, and a credential file's path went out with an
/// innocent task's pid — `NN-L-FIM-011`/`014` kill that pid, and the
/// FIM-010..017 records are posture floors.
#[map]
static OPEN_TASK: HashMap<u64, OpenTask> =
    HashMap::with_max_entries(crate::task_scratch::TASK_SCRATCH_CAP, 0);
/// Interesting opens only: a few per second on a busy host.
#[map]
pub static OPEN_SENSOR_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);
/// Lab PR 225: per-tgid windows of renames to one new extension.
#[map]
static OPEN_RENAMES: LruHashMap<u32, RenameWindow> = LruHashMap::with_max_entries(4096, 0);
/// Lab PR 225: per-tgid unlink windows.
#[map]
static OPEN_UNLINKS: LruHashMap<u32, UnlinkWindow> = LruHashMap::with_max_entries(4096, 0);
/// Lab PR 225: both names of a rename, never on the stack, and the two
/// names' extensions ([`name_ext`]), slots [`EXT_NEW`] and [`EXT_OLD`] of
/// `ext`: `[hash, length]` each, written by [`nn_rename_ext`], read by
/// [`nn_rename_shape`] and the window.
#[repr(C)]
pub(crate) struct RenameTask {
    names: RenameNames,
    ext: [u64; 4],
}
/// Lot 322 (the review of #546, F3): [`RenameTask`] is the renaming task's
/// own entry (keyed by its `task_struct`), made and removed in one run of
/// [`nn_rename_burst`]: per CPU, the burst behind `NN-L-FIM-010` (a
/// posture floor) could count another task's rename.
#[map]
static RENAME_TASK: HashMap<u64, RenameTask> =
    HashMap::with_max_entries(crate::task_scratch::TASK_SCRATCH_CAP, 0);
const EXT_NEW: usize = 0;
const EXT_OLD: usize = 2;

#[inline(always)]
pub fn armed() -> bool {
    matches!(OPEN_SENSOR.get(0), Some(v) if *v == OPEN_SENSOR_ARMED)
}

#[inline(always)]
pub(crate) unsafe fn read_ptr(p: *const u8) -> *const u8 {
    match bpf_probe_read_kernel::<*const u8>(p as *const *const u8) {
        Ok(v) => v,
        Err(_) => core::ptr::null(),
    }
}

/// `u64` at `src`, 0 when unreadable, without a branch on the result: the
/// helper always writes its destination (zeros on a fault). The ancestor
/// walk reads this way, since every branch there multiplies the states
/// the 5.15 verifier explores, and a zero is harmless where it lands (no
/// rule has device 0, no name is empty).
#[inline(always)]
unsafe fn peek_u64(src: *const u8) -> u64 {
    let mut v = core::mem::MaybeUninit::<u64>::uninit();
    let _ = generated::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 8, src as *const c_void);
    v.assume_init()
}

#[inline(always)]
unsafe fn peek_u32(src: *const u8) -> u32 {
    let mut v = core::mem::MaybeUninit::<u32>::uninit();
    let _ = generated::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 4, src as *const c_void);
    v.assume_init()
}

/// `dentry->d_name.name` into `dst[..32]`, NUL-padded, the same way
/// (an unreadable name stays all zeros).
#[inline(always)]
unsafe fn peek_name(dentry: *const u8, name_off: usize, dst: *mut u8) {
    zero32(dst);
    let name = peek_u64(dentry.add(name_off)) as *const c_void;
    let _ = generated::bpf_probe_read_kernel_str(dst as *mut c_void, OPEN_NAME_LEN as u32, name);
}

/// `(dev, ino)` of `inode` as `stat()` reports it (review 55); dev 0 /
/// ino 0 when unreadable — a plain value, never an `Option` across the
/// inlined calls (5.15 rule 3).
#[inline(always)]
pub(crate) unsafe fn key_of(inode: *const u8) -> InodeKey {
    let mut key = InodeKey { dev: 0, ino: 0 };
    if inode.is_null() {
        return key;
    }
    let sb = read_ptr(inode.add(off!(INODE_I_SB_OFFSET)));
    if sb.is_null() {
        return key;
    }
    if let Ok(dev) = bpf_probe_read_kernel::<u32>(sb.add(off!(SUPER_BLOCK_S_DEV_OFFSET)) as *const u32) {
        key.dev = crate::inode_dev::stat_dev(inode, sb, dev) as u64;
    }
    if let Ok(ino) = bpf_probe_read_kernel::<u64>(inode.add(off!(INODE_I_INO_OFFSET)) as *const u64) {
        key.ino = ino;
    }
    key
}

/// `dentry->d_name.name` into `dst[..32]`, NUL-padded.
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
        let slot = core::slice::from_raw_parts_mut(dst, OPEN_NAME_LEN);
        let _ = bpf_probe_read_kernel_str_bytes(name, slot);
    }
}

#[inline(always)]
unsafe fn zero32(dst: *mut u8) {
    let w = dst as *mut u64;
    core::ptr::write_volatile(w, 0);
    core::ptr::write_volatile(w.add(1), 0);
    core::ptr::write_volatile(w.add(2), 0);
    core::ptr::write_volatile(w.add(3), 0);
}

#[inline(always)]
unsafe fn copy32(dst: *mut u8, src: *const u8) {
    let d = dst as *mut u64;
    let s = src as *const u64;
    core::ptr::write_volatile(d, core::ptr::read_volatile(s));
    core::ptr::write_volatile(d.add(1), core::ptr::read_volatile(s.add(1)));
    core::ptr::write_volatile(d.add(2), core::ptr::read_volatile(s.add(2)));
    core::ptr::write_volatile(d.add(3), core::ptr::read_volatile(s.add(3)));
}

#[inline(always)]
fn rule(key: &InodeKey) -> u32 {
    match unsafe { OPEN_RULES.get(key) } {
        Some(r) => *r,
        None => 0,
    }
}

/// `true` for the superblock magic of a filesystem whose writes do not
/// count (sysfs, procfs, …).
#[inline(always)]
fn carveout_magic(magic: u64) -> bool {
    let mut i = 0;
    while i < CARVEOUT_MAGICS.len() {
        if CARVEOUT_MAGICS[i] == magic {
            return true;
        }
        i += 1;
    }
    false
}

/// The class of directory `dir` (key `dkey`), from the cache or by
/// walking its ancestors ([`nn_open_walk`]).
#[inline(always)]
unsafe fn dir_class(dkey: &InodeKey, dir: *const u8, dir_inode: *const u8) -> DirClass {
    let gen = match DIR_CLASS_GEN.get(0) {
        Some(g) => *g,
        None => 0,
    };
    if let Some(c) = DIR_CLASS.get(dkey) {
        if c.gen == gen && c.bits & CLASSIFIED != 0 {
            return *c;
        }
    }
    let r = nn_open_walk(dkey.dev, dkey.ino, dir as u64, dir_inode as u64);
    let c = DirClass {
        bits: r as u32 | CLASSIFIED,
        uid: (r >> 32) as u32,
        gen,
        _pad: 0,
    };
    let _ = DIR_CLASS.insert(dkey, &c, 0);
    c
}

/// Lot 282 (the re-review of #500): the class of the directory of
/// `parent` (a dentry; on `key`'s filesystem), from the cache, computed and
/// cached on a miss ([`dir_class`]); `None` when it cannot be read. Lot
/// 283c: the unlink counter reads its owner bits too ([`own_of`]).
#[inline(always)]
unsafe fn parent_class(key: &InodeKey, parent: *const u8) -> Option<DirClass> {
    let parent_inode = read_ptr(parent.add(off!(DENTRY_D_INODE_OFFSET)));
    if parent_inode.is_null() {
        return None;
    }
    let pkey = InodeKey {
        dev: key.dev,
        ino: match bpf_probe_read_kernel::<u64>(parent_inode.add(off!(INODE_I_INO_OFFSET)) as *const u64) {
            Ok(i) => i,
            Err(_) => return None,
        },
    };
    Some(dir_class(&pkey, parent, parent_inode))
}

/// The owner (`i_uid`) of `inode`, or `u32::MAX` (no account's) when it
/// cannot be read.
#[inline(always)]
unsafe fn inode_uid(inode: *const u8) -> u32 {
    if inode.is_null() {
        return u32::MAX;
    }
    match off_opt!(INODE_I_UID_OFFSET) {
        Some(o) => bpf_probe_read_kernel::<u32>(inode.add(o) as *const u32).unwrap_or(u32::MAX),
        None => u32::MAX,
    }
}

/// Lot 283c: the [`own_code`] of the file of `dentry` (written, or
/// destroyed) in a directory of class `bits` (owner `owner`) by the
/// current task: its uid, the owners of the file and of its directory as
/// the kernel resolved them (the dentry's parent), its links. Nothing is
/// read outside a class [`own_code`] reads.
#[inline(always)]
unsafe fn own_of(bits: u32, owner: u32, dentry: *const u8) -> u32 {
    if bits & OWN_DATA_BITS == 0 || dentry.is_null() {
        return 0;
    }
    let inode = read_ptr(dentry.add(off!(DENTRY_D_INODE_OFFSET)));
    let parent = read_ptr(dentry.add(off!(DENTRY_D_PARENT_OFFSET)));
    if inode.is_null() || parent.is_null() {
        return 0;
    }
    let nlink = match off_opt!(INODE_I_NLINK_OFFSET) {
        Some(o) => bpf_probe_read_kernel::<u32>(inode.add(o) as *const u32).unwrap_or(0),
        None => 0,
    };
    let dir_uid = inode_uid(read_ptr(parent.add(off!(DENTRY_D_INODE_OFFSET))));
    let uid = (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32;
    own_code(bits, owner, uid, dir_uid, inode_uid(inode), nlink)
}

/// The ancestor walk of [`dir_class`]: class bits in the low half, the
/// runtime directory's owner (or `u32::MAX`) in the high half.
/// `DEPTH_CAPPED` when [`OPEN_CLASSIFY_DEPTH`] levels did not reach the
/// filesystem root.
///
/// A global BPF function (exported, never inlined, scalar arguments): the
/// verifier checks it once, on its own, and the sensor sees one unknown
/// return value. Inlined, its eight levels (sixteen since external audit
/// EBPF-011) multiplied the states of the rest of the program past the
/// 5.15 verifier's million-instruction budget. Every argument is a plain
/// value, so any value is safe.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_open_walk(dev: u64, ino: u64, dir: u64, dir_inode: u64) -> u64 {
    unsafe { walk(InodeKey { dev, ino }, dir as *const u8, dir_inode as *const u8) }
}

#[inline(always)]
unsafe fn walk(start: InodeKey, dir: *const u8, dir_inode: *const u8) -> u64 {
    // The running task's buffers: [`on_open`]'s, or made here for an
    // unlink or a rename (`forget_task` removes them).
    let task = bpf_get_current_task();
    let scratch = match crate::task_scratch::get_or_make(&OPEN_TASK, &task) {
        Some(p) => (*p).names.as_mut_ptr(),
        None => {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::OPEN_SENSOR);
            return u64::from(u32::MAX) << 32;
        }
    };
    let mut bits = 0u32;
    let mut uid = u32::MAX;
    // The walk never leaves the directory's superblock: the layout, the
    // magic and the device are read once. Only btrfs subvolumes change
    // the device on the way up (review 55), and only there is it read per
    // level. Every read inside the loop is branch-free (`peek_*`).
    let o_parent = off!(DENTRY_D_PARENT_OFFSET);
    let o_inode = off!(DENTRY_D_INODE_OFFSET);
    let o_name = off!(DENTRY_D_NAME_OFFSET) + off!(QSTR_NAME_OFFSET);
    let o_ino = off!(INODE_I_INO_OFFSET);
    let sb = peek_u64(dir_inode.add(off!(INODE_I_SB_OFFSET))) as *const u8;
    let magic = peek_u64(sb.add(off!(SUPER_BLOCK_S_MAGIC_OFFSET)));
    if carveout_magic(magic) {
        bits |= TREE_CARVEOUT;
    }
    let btrfs = magic == BTRFS_SUPER_MAGIC;
    let s_dev = peek_u32(sb.add(off!(SUPER_BLOCK_S_DEV_OFFSET)));
    let mut d = dir;
    let mut key = start;
    let mut capped = DEPTH_CAPPED;
    for level in 0..OPEN_CLASSIFY_DEPTH {
        // Level 0 is the directory itself (its children's rules apply);
        // above it only what a directory passes to its whole subtree.
        let keep = if level == 0 { DIRECT } else { SUBTREE };
        let r = rule(&key);
        bits |= r & keep;
        // Lot 283c: a person's cache directory carries its owner the
        // same way.
        if r & (TREE_RUNTIME | TREE_USER_CACHE) != 0 {
            if let Some(u) = RUNTIME_UIDS.get(&key) {
                uid = *u;
            }
        }
        let up = peek_u64(d.add(o_parent)) as *const u8;
        if up.is_null() || up == d {
            capped = 0;
            break;
        }
        // (registered parent, this name): paths missing at registration.
        peek_name(d, o_name, scratch);
        let up_inode = peek_u64(up.add(o_inode)) as *const u8;
        let up_key = InodeKey {
            dev: if btrfs {
                crate::inode_dev::stat_dev(up_inode, sb, s_dev) as u64
            } else {
                s_dev as u64
            },
            ino: peek_u64(up_inode.add(o_ino)),
        };
        let ck = scratch.add(64);
        core::ptr::write_volatile(ck as *mut u64, up_key.dev);
        core::ptr::write_volatile((ck as *mut u64).add(1), up_key.ino);
        copy32(ck.add(16), scratch);
        if let Some(cr) = CHILD_RULES.get(&*(ck as *const ChildRuleKey)) {
            bits |= *cr & keep;
        }
        // Credential directory names: this name with its parent's name,
        // then with any parent.
        peek_name(up, o_name, scratch.add(OPEN_NAME_LEN));
        let nr = match OPEN_NAME_RULES.get(&*(scratch as *const [u8; 2 * OPEN_NAME_LEN])) {
            Some(v) => *v,
            None => {
                zero32(scratch.add(OPEN_NAME_LEN));
                match OPEN_NAME_RULES.get(&*(scratch as *const [u8; 2 * OPEN_NAME_LEN])) {
                    Some(v) => *v,
                    None => 0,
                }
            }
        };
        bits |= nr & (if level == 0 { TREE_CRED | LEAVES_CRED } else { TREE_CRED });
        d = up;
        key = up_key;
    }
    if capped != 0 {
        if let Some(n) = OPEN_DEPTH_CAPPED.get_ptr_mut(0) {
            *n += 1;
        }
    }
    (u64::from(uid) << 32) | u64::from(bits | capped)
}

/// The writer's login uid, or `u32::MAX` (never a runtime dir's owner)
/// when the kernel has none.
#[inline(always)]
unsafe fn loginuid() -> u32 {
    let task = bpf_get_current_task() as *const u8;
    match off_opt!(TASK_STRUCT_LOGINUID_OFFSET) {
        Some(o) if !task.is_null() => match bpf_probe_read_kernel::<u32>(task.add(o) as *const u32) {
            Ok(u) => u,
            Err(_) => u32::MAX,
        },
        _ => u32::MAX,
    }
}

/// The write-open counts of the sensor, and the record of a crossing:
/// `cls` is the parent directory's [`DirClass`] (bits in the low half, the
/// runtime directory's owner in the high half), `dentry` the opened file's
/// dentry, `dev_over` its device with, lot 282, three flags: bit 63 the
/// file held data when opened (its size not zero, read before `O_TRUNC`
/// empties it), bit 62 the open created it (`FMODE_CREATED`), bit 61 its
/// size is at least [`OVERWRITE_MIN_BYTES`] (external audit POS-002, lab PR
/// 127) — `ino` its inode number, `flags_mode` its
/// `f_flags` and, in the high half, its `f_mode`. When a window crosses
/// its threshold ([`count_write`]) the record is emitted here — `reason`
/// the mass-write bits, `count` the window's — unless the writer is the
/// agent itself. Returns 0.
///
/// A global BPF function, like [`nn_open_walk`], whose result the sensor
/// ignores (lab PR 137, instructions the 5.15 verifier processed for
/// `fim_file_open_sensor`): folded back into the sensor's `reason` the
/// count cost 80,000 to 110,000 more, and the count inline with the
/// cgroup window went past the million. Here its windows and branches are
/// verified once, on their own.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_open_count_write(cls: u64, dentry: u64, dev_over: u64, ino: u64, flags_mode: u64) -> u64 {
    unsafe {
        let key = InodeKey {
            dev: dev_over & !(7u64 << 61),
            ino,
        };
        let r = count_write(
            cls as u32,
            (cls >> 32) as u32,
            dev_over >> 63 != 0,
            (dev_over >> 62) & 1 != 0,
            (dev_over >> 61) & 1 != 0,
            &key,
            dentry as *const u8,
        );
        let reason = r as u32;
        if reason != 0 && !crate::fim_watch::caller_is_in_family() {
            emit(
                reason,
                &key,
                dentry as *const u8,
                flags_mode as u32,
                (flags_mode >> 32) as u32,
                (r >> 32) as u32,
            );
        }
    }
    0
}

/// Count a write-open per tgid and, for an overwrite, per cgroup (external
/// audit EBPF-011). Returns the [`open_reason`] bits this open adds in the
/// low half — `MASS_WRITE` / `MASS_OVERWRITE` / `MASS_OVERWRITE_SMALL`
/// when the tgid's window crosses a threshold, `MASS_OVERWRITE_CGROUP`
/// when its cgroup's does, each once per window — and the count in the
/// high half (the cgroup's overwrites when that window crossed, else the
/// tgid's: the files it rewrote, or wrote new). Lot 282: each file counts
/// once per window ([`OPEN_OVERWRITE_SEEN`]), as [`write_kind`] reads its
/// first write-open — `data`: it held data, `created`: the open created
/// it, `big`: at least [`OVERWRITE_MIN_BYTES`]. Lot 283c: each window keeps
/// the [`own_after`] summary of the files it counted ([`own_of`] of
/// `dentry`, the opened file's), and a crossing carries its window's in
/// the reason's top byte ([`open_reason::OWN_SHIFT`]).
#[inline(always)]
unsafe fn count_write(
    cls_bits: u32,
    cls_uid: u32,
    data: bool,
    created: bool,
    big: bool,
    key: &InodeKey,
    dentry: *const u8,
) -> u64 {
    if carved_class(cls_bits, cls_uid, || loginuid()) {
        return 0;
    }
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = bpf_ktime_get_ns();
    if created {
        let made = OverwriteSeenKey {
            tgid,
            _pad: 0,
            dev: key.dev,
            ino: key.ino,
        };
        let _ = OPEN_CREATED.insert(&made, &now, 0);
    }
    let window = OPEN_WRITES.get_ptr_mut(&tgid);
    let start = match window {
        Some(w) => (*w).start_for(now),
        None => now,
    };
    let seen = OverwriteSeenKey {
        tgid,
        _pad: 0,
        dev: key.dev,
        ino: key.ino,
    };
    // The re-review of #500 (cost): a file the open created is new — its
    // first write-open of the window, whatever an entry of a freed inode
    // number says — so it is remembered without a lookup.
    let first = first_write(created, || OPEN_OVERWRITE_SEEN.get(&seen).copied(), start);
    if first {
        let _ = OPEN_OVERWRITE_SEEN.insert(&seen, &start, 0);
    }
    let kind = write_kind(created, data, big, first);
    let counted = kind != WriteKind::Repeat;
    let own = if counted { own_of(cls_bits, cls_uid, dentry) } else { 0 };
    let (mut reason, mut count, cg_add, mut summary) = match window {
        Some(w) => {
            let (r, c, a) = write_step(&mut *w, kind, now);
            // `write_step` starts a fresh window with one write-open.
            (*w).own = own_after((*w).own, (*w).count == 1, counted, own);
            (r, c, a, (*w).own)
        }
        None => {
            let mut fresh = OpenWriteWindow::fresh(now, kind);
            fresh.own = own;
            let _ = OPEN_WRITES.insert(&tgid, &fresh, 0);
            (0, 0, 0, own)
        }
    };
    if cg_add != 0 {
        let (n, cg_own) = count_cgroup(cg_add, summary, now);
        if n != 0 {
            reason |= open_reason::MASS_OVERWRITE_CGROUP;
            count = n;
            summary = cg_own;
        }
    }
    if reason != 0 {
        reason |= (summary & 0xFF) << open_reason::OWN_SHIFT;
    }
    (u64::from(count) << 32) | u64::from(reason)
}

/// `add` overwrites into the writer's cgroup window; the window's
/// overwrites when they cross the threshold, else 0, and (lot 283c) the
/// window's [`own_after`] summary with the process's `own`. A writer in the
/// root cgroup (no cgroup v2 hierarchy in use) is keyed by uid and login
/// uid.
#[inline(always)]
unsafe fn count_cgroup(add: u32, own: u32, now: u64) -> (u32, u32) {
    let cgroup = bpf_get_current_cgroup_id();
    let key = if cgroup > 1 {
        OpenCgKey {
            cgroup,
            uid: 0,
            loginuid: 0,
        }
    } else {
        OpenCgKey {
            cgroup: 0,
            uid: (bpf_get_current_uid_gid() & 0xFFFF_FFFF) as u32,
            loginuid: loginuid(),
        }
    };
    match OPEN_CG_WRITES.get_ptr_mut(&key) {
        Some(w) => {
            let n = cgroup_step(&mut *w, add, now);
            // A fresh window holds this add alone (every add is one or more).
            (*w).own = own_after((*w).own, (*w).overwrites == add, true, own);
            (n, (*w).own)
        }
        None => {
            let w = OpenCgWindow {
                start_ns: now,
                overwrites: add,
                fired: 0,
                own,
                _pad: 0,
            };
            let _ = OPEN_CG_WRITES.insert(&key, &w, 0);
            (0, own)
        }
    }
}

/// `u64` at `off` of a window read from `src`; a field past the window is
/// read on its own, so no kernel layout can make it wrong. `len` must be a
/// constant: the verifier bounds `off` only when the compiler folds
/// `off + 8 <= len` into a comparison of `off` itself.
#[inline(always)]
unsafe fn win_u64(win: *const u8, len: usize, src: *const u8, off: usize) -> u64 {
    if off + 8 <= len {
        core::ptr::read_unaligned(win.add(off) as *const u64)
    } else {
        match bpf_probe_read_kernel::<u64>(src.add(off) as *const u64) {
            Ok(v) => v,
            Err(_) => 0,
        }
    }
}

#[inline(always)]
unsafe fn win_u32(win: *const u8, len: usize, src: *const u8, off: usize) -> u32 {
    if off + 4 <= len {
        core::ptr::read_unaligned(win.add(off) as *const u32)
    } else {
        match bpf_probe_read_kernel::<u32>(src.add(off) as *const u32) {
            Ok(v) => v,
            Err(_) => 0,
        }
    }
}

/// `struct file` into `w[..FILE_WIN]` and its inode into the next
/// `INODE_WIN` bytes; the inode, or null when either window cannot be read
/// whole (it would end in an unmapped page, e.g. the KFENCE guard page
/// after a small `struct file`).
#[inline(always)]
unsafe fn read_windows(file: *const u8, w: *mut u8) -> *const u8 {
    if bpf_probe_read_kernel_buf(file, core::slice::from_raw_parts_mut(w, FILE_WIN)).is_err() {
        return core::ptr::null();
    }
    let inode = win_u64(w, FILE_WIN, file, off!(FILE_F_INODE_OFFSET)) as *const u8;
    if inode.is_null()
        || bpf_probe_read_kernel_buf(inode, core::slice::from_raw_parts_mut(w.add(FILE_WIN), INODE_WIN))
            .is_err()
    {
        return core::ptr::null();
    }
    inode
}

/// The whole `file_open` work of the sensor variant of the FIM observer
/// (`fim_watch::fim_file_open_sensor`): the FIM watch and the sensor, from
/// one read of `struct file` and one of the inode, in the running task's
/// own buffers ([`OPEN_TASK`]), removed at the end.
#[inline(always)]
pub unsafe fn on_open(file: *const u8) {
    let task = bpf_get_current_task();
    let t = match crate::task_scratch::make(&OPEN_TASK, &task) {
        Some(p) => p,
        None => {
            // The map full: FIM still sees the open (the plain observer,
            // field by field, no shared buffer); the sensor's look is
            // lost, counted.
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::OPEN_SENSOR);
            crate::fim_watch::observe_open_plain(file);
            return;
        }
    };
    on_open_in(file, t);
    let _ = OPEN_TASK.remove(&task);
}

#[inline(always)]
unsafe fn on_open_in(file: *const u8, t: *mut OpenTask) {
    let w = (*t).win.as_mut_ptr();
    let inode = read_windows(file, w);
    if inode.is_null() {
        // No windows: FIM still sees the open, field by field as the
        // plain observer reads it; only the sensor skips it.
        crate::fim_watch::observe_open_plain(file);
        return;
    }
    let iw = w.add(FILE_WIN);
    let sb = win_u64(iw, INODE_WIN, inode, off!(INODE_I_SB_OFFSET)) as *const u8;
    if sb.is_null() {
        return;
    }
    let ino = win_u64(iw, INODE_WIN, inode, off!(INODE_I_INO_OFFSET));
    let s_dev = match bpf_probe_read_kernel::<u32>(sb.add(off!(SUPER_BLOCK_S_DEV_OFFSET)) as *const u32) {
        Ok(d) => d,
        Err(_) => return,
    };
    let key = InodeKey {
        dev: crate::inode_dev::stat_dev(inode, sb, s_dev) as u64,
        ino,
    };
    let mode = win_u32(w, FILE_WIN, file, off!(FILE_F_MODE_OFFSET));
    let watched = crate::fim_watch::WATCHED_PATHS.get(&key).is_some();
    if watched {
        // The agent's own opens: neither FIM nor the sensor reports them.
        if crate::fim_watch::caller_is_in_family() {
            return;
        }
        // Review 75: a read-only repeat by the same task is dropped.
        if mode & FMODE_WRITE != 0 || !crate::read_repeat::repeat(&crate::fim_watch::FIM_READ_SEEN, &key) {
            crate::fim_watch::emit_drift(FIM_OP_OPENED, key);
        }
    }
    if !armed() {
        return;
    }
    let dentry = win_u64(w, FILE_WIN, file, off!(FILE_F_PATH_OFFSET) + off!(PATH_DENTRY_OFFSET)) as *const u8;
    let flags = win_u32(w, FILE_WIN, file, off!(FILE_F_FLAGS_OFFSET));
    // Mass write is the ransomware shape — data files. A device, FIFO or
    // socket opened for writing (`> /dev/null` in a script loop, systemd
    // writing `/dev/console` at shutdown) does not count.
    let regular = (win_u32(iw, INODE_WIN, inode, off!(INODE_I_MODE_OFFSET)) as u16) & S_IFMT == S_IFREG;
    let size = win_u64(iw, INODE_WIN, inode, off!(INODE_I_SIZE_OFFSET));
    observe(&key, watched, watched, mode, flags, dentry, regular, size, (*t).names.as_mut_ptr());
}

/// The sensor proper. `family_checked`: the caller already knows the
/// opener is not the agent itself.
#[inline(always)]
unsafe fn observe(
    key: &InodeKey,
    watched: bool,
    family_checked: bool,
    mode: u32,
    flags: u32,
    dentry: *const u8,
    regular: bool,
    size: u64,
    scratch: *mut u8,
) {
    let write = mode & FMODE_WRITE != 0;
    if dentry.is_null() {
        return;
    }
    let parent = read_ptr(dentry.add(off!(DENTRY_D_PARENT_OFFSET)));
    if parent.is_null() || parent == dentry {
        return;
    }
    let parent_inode = read_ptr(parent.add(off!(DENTRY_D_INODE_OFFSET)));
    if parent_inode.is_null() {
        return;
    }
    // The parent is on the file's filesystem (and, on btrfs, in its
    // subvolume): only its inode number is read.
    let pkey = InodeKey {
        dev: key.dev,
        ino: match bpf_probe_read_kernel::<u64>(parent_inode.add(off!(INODE_I_INO_OFFSET)) as *const u64) {
            Ok(i) => i,
            Err(_) => return,
        },
    };
    let cls = dir_class(&pkey, parent, parent_inode);
    // A file's own rule only where userland put one (DIR_HAS_FILES).
    let mut own = if cls.bits & DIR_HAS_FILES != 0 { rule(key) } else { 0 };

    // The leaf name, only where it matters: credential leaves (not for
    // an inode the FIM path already reports) and missing-file rules.
    let leaf_cred = !watched && cls.bits & (LEAVES_CRED | TREE_HOME) != 0;
    let mut cred = !watched && cls.bits & TREE_CRED != 0;
    if leaf_cred || cls.bits & CHILD_FILES != 0 {
        read_name(dentry, scratch);
        if cls.bits & CHILD_FILES != 0 {
            let ck = scratch.add(64);
            core::ptr::write_volatile(ck as *mut u64, pkey.dev);
            core::ptr::write_volatile((ck as *mut u64).add(1), pkey.ino);
            copy32(ck.add(16), scratch);
            if let Some(cr) = CHILD_RULES.get(&*(ck as *const ChildRuleKey)) {
                own |= *cr;
            }
        }
        if leaf_cred && !cred {
            // (leaf, parent name) where the parent's name decides
            // (`.aws/credentials`), then (leaf, any) in home trees.
            if cls.bits & LEAVES_CRED != 0 {
                read_name(parent, scratch.add(OPEN_NAME_LEN));
                if let Some(v) = OPEN_NAME_RULES.get(&*(scratch as *const [u8; 2 * OPEN_NAME_LEN])) {
                    cred = *v & LEAF_CRED != 0;
                }
            }
            if !cred {
                zero32(scratch.add(OPEN_NAME_LEN));
                if let Some(v) = OPEN_NAME_RULES.get(&*(scratch as *const [u8; 2 * OPEN_NAME_LEN])) {
                    cred = *v & LEAF_CRED != 0;
                }
            }
            if !cred && cls.bits & TREE_HOME != 0 {
                cred = kdbx_suffix(&*(scratch as *const [u8; OPEN_NAME_LEN]));
            }
        }
    }

    let mut reason = 0u32;
    if own & FILE_SENSITIVE != 0 {
        reason |= open_reason::SENSITIVE;
    }
    if write && (own & FILE_CRITICAL != 0 || cls.bits & TREE_CRITICAL != 0) {
        reason |= open_reason::CRITICAL;
    }
    if write && (own & FILE_PERSIST != 0 || cls.bits & TREE_PERSIST != 0) {
        reason |= open_reason::PERSIST;
    }
    if cls.bits & CHILDREN_PROBE != 0 {
        reason |= open_reason::PROBE;
    }
    if cred {
        reason |= open_reason::CRED;
    }
    // Write-opens are counted before the family lookup; a crossing is
    // emitted by the count itself, as a record of its own, and the agent's
    // own writes are dropped there (once per window).
    // Lab PR 137, 5.15 verifier budget: nothing of the count comes back
    // here, and no value of `cls.bits` is folded into `reason` (the depth
    // cap is counted in the walk). The branches below test `reason`: an
    // unknown folded into it keeps alive the paths that report nothing,
    // and a class bit folded into it is made precise back to the map read,
    // so states stop merging. The second took `fim_file_open_sensor` past
    // the million instructions.
    if write && regular {
        let created = mode & FMODE_CREATED != 0;
        let _ = nn_open_count_write(
            u64::from(cls.bits) | (u64::from(cls.uid) << 32),
            dentry as u64,
            key.dev
                | (u64::from(size != 0) << 63)
                | (u64::from(created) << 62)
                | (u64::from(size >= OVERWRITE_MIN_BYTES) << 61),
            key.ino,
            u64::from(flags) | (u64::from(mode) << 32),
        );
    }
    if reason == 0 {
        return;
    }
    if !family_checked && crate::fim_watch::caller_is_in_family() {
        return;
    }
    // Review 75: a read-only repeat by the same task is dropped (the
    // telemetry probe excepted: each of its opens is a check).
    if !write && reason & open_reason::PROBE == 0 && crate::read_repeat::repeat(&OPEN_READ_SEEN, key) {
        return;
    }
    emit(reason, key, dentry, flags, mode, 0);
}

/// The one emit site: identity, reason and the mount-relative path, plus
/// the key of the walk's top (a filesystem root) for userland's mount
/// lookup. Through [`nn_open_emit`].
#[inline(always)]
unsafe fn emit(reason: u32, key: &InodeKey, dentry: *const u8, flags: u32, mode: u32, count: u32) {
    let _ = nn_open_emit(
        u64::from(reason) | (u64::from(count) << 32),
        key.dev,
        key.ino,
        dentry as u64,
        u64::from(flags) | (u64::from(mode) << 32),
    );
}

/// [`emit`] as a global BPF function (lab PR 137): `reason_count` is the
/// reason with the count in the high half, `flags_mode` the flags with the
/// mode in the high half. Inlined, its sixteen-slot path walk was verified
/// again for every distinct state that reached it; here once. On 5.15
/// `fim_file_open_sensor` went from 834,000 processed instructions (main)
/// to 463,000, `fim_file_cap_observe` from 55,000 to 8,000. The ring entry
/// never leaves it (5.15 rule 1), and every argument is a plain value.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_open_emit(reason_count: u64, dev: u64, ino: u64, dentry: u64, flags_mode: u64) -> u64 {
    unsafe {
        emit_record(
            reason_count as u32,
            &InodeKey { dev, ino },
            dentry as *const u8,
            flags_mode as u32,
            (flags_mode >> 32) as u32,
            (reason_count >> 32) as u32,
        )
    };
    0
}

#[inline(always)]
unsafe fn emit_record(reason: u32, key: &InodeKey, dentry: *const u8, flags: u32, mode: u32, count: u32) {
    let mut entry = match OPEN_SENSOR_EVENTS.reserve::<OpenRecordRaw>(0) {
        Some(e) => e,
        None => {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::OPEN_SENSOR);
            return;
        }
    };
    let raw: *mut OpenRecordRaw = entry.as_mut_ptr();
    crate::zero::zero(raw);
    (*raw).timestamp_ns = bpf_ktime_get_ns();
    (*raw).pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    (*raw).uid = (uid_gid & 0xFFFF_FFFF) as u32;
    (*raw).gid = (uid_gid >> 32) as u32;
    crate::comm::comm_into(&mut (*raw).comm);
    (*raw).dev = key.dev;
    (*raw).ino = key.ino;
    (*raw).flags = flags;
    (*raw).mode = mode;
    // Lot 283c: a crossing's own-data summary rides in the reason's top
    // byte.
    (*raw).reason = reason & open_reason::REASON_BITS;
    (*raw).own = (reason >> open_reason::OWN_SHIFT) as u8;
    (*raw).count = count;
    // Lot 282 (the review of #500, C1): the replacement's halves are
    // paired per cgroup too.
    (*raw).cgroup = bpf_get_current_cgroup_id();
    let dst = (*raw).path.as_mut_ptr();
    let mut d = dentry;
    let mut n: usize = 0;
    let mut top: *const u8 = core::ptr::null();
    for i in 0..OPEN_PATH_SLOTS {
        if d.is_null() {
            break;
        }
        let name = read_ptr(d.add(off!(DENTRY_D_NAME_OFFSET) + off!(QSTR_NAME_OFFSET)));
        if !name.is_null() {
            let slot = core::slice::from_raw_parts_mut(dst.add(i * OPEN_PATH_SLOT_LEN), OPEN_PATH_SLOT_LEN);
            let _ = bpf_probe_read_kernel_str_bytes(name, slot);
        }
        n = i + 1;
        let up = read_ptr(d.add(off!(DENTRY_D_PARENT_OFFSET)));
        if up == d {
            top = d;
            break;
        }
        d = up;
    }
    (*raw).path_n = n as u16;
    if top.is_null() {
        (*raw).path_truncated = 1;
    } else {
        let root = key_of(read_ptr(top.add(off!(DENTRY_D_INODE_OFFSET))));
        (*raw).root_dev = root.dev;
        (*raw).root_ino = root.ino;
    }
    entry.submit(0);
}

/// Bump the cache generation: every cached class is stale.
#[inline(always)]
pub fn bump_generation() {
    if let Some(g) = DIR_CLASS_GEN.get_ptr_mut(0) {
        unsafe { *g = (*g).wrapping_add(1) };
    }
}

/// `inode_rename` (from `fim_rename_observe`): moving a directory changes
/// the class of everything below it.
#[inline(always)]
pub unsafe fn on_rename(moved_inode: *const u8) {
    if !armed() || moved_inode.is_null() {
        return;
    }
    if let Ok(m) = bpf_probe_read_kernel::<u16>(moved_inode.add(off!(INODE_I_MODE_OFFSET)) as *const u16) {
        if m & S_IFMT == S_IFDIR {
            bump_generation();
        }
    }
}

/// `rmdir`: the removed directory's inode number can be reused for a new
/// directory elsewhere, which must not inherit its cached class. Only
/// that entry goes: an `rm -rf` of a large tree would otherwise empty the
/// whole cache once per directory. Nothing else can be stale, since a
/// directory being removed is empty. The hook runs before the removal,
/// so a refused `rmdir` costs one reclassification.
#[lsm(hook = "inode_rmdir")]
pub fn open_sensor_rmdir(ctx: LsmContext) -> i32 {
    unsafe { try_open_sensor_rmdir(&ctx) }
}

#[inline(always)]
unsafe fn try_open_sensor_rmdir(ctx: &LsmContext) -> i32 {
    // Kernel signature: (dir, dentry).
    if !armed() {
        return 0;
    }
    let dentry: *const u8 = ctx.arg(1);
    if dentry.is_null() {
        return 0;
    }
    let key = key_of(read_ptr(dentry.add(off!(DENTRY_D_INODE_OFFSET))));
    if key.ino != 0 {
        let _ = DIR_CLASS.remove(&key);
    }
    0
}

/// Lab PR 225: the name of `dentry` into `p` — its first
/// [`NAME_HEAD_LEN`] − 1 bytes, NUL-padded, its last [`NAME_TAIL_LEN`] and
/// its length. An unreadable name stays empty (length 0), which no rename
/// shape counts.
#[inline(always)]
unsafe fn read_parts(dentry: *const u8, p: *mut NameParts) {
    let head = core::ptr::addr_of_mut!((*p).head) as *mut u8;
    let tail = core::ptr::addr_of_mut!((*p).tail) as *mut u8;
    let mut i = 0;
    while i < NAME_HEAD_LEN {
        core::ptr::write_volatile(head.add(i), 0);
        i += 1;
    }
    (*p).len = 0;
    (*p).tail_len = 0;
    let name = read_ptr(dentry.add(off!(DENTRY_D_NAME_OFFSET) + off!(QSTR_NAME_OFFSET)));
    if name.is_null() {
        return;
    }
    let len = match bpf_probe_read_kernel::<u32>(
        dentry.add(off!(DENTRY_D_NAME_OFFSET) + off!(QSTR_LEN_OFFSET)) as *const u32,
    ) {
        Ok(l) => l,
        Err(_) => return,
    };
    let _ = bpf_probe_read_kernel_str_bytes(name, core::slice::from_raw_parts_mut(head, NAME_HEAD_LEN));
    if len as usize > NAME_TAIL_LEN {
        let dst = core::slice::from_raw_parts_mut(tail, NAME_TAIL_LEN);
        if bpf_probe_read_kernel_buf(name.add(len as usize - NAME_TAIL_LEN), dst).is_err() {
            return;
        }
        (*p).tail_len = NAME_TAIL_LEN as u32;
    } else {
        let mut j = 0;
        while j < NAME_TAIL_LEN {
            core::ptr::write_volatile(tail.add(j), core::ptr::read_volatile(head.add(j)));
            j += 1;
        }
        (*p).tail_len = len;
    }
    (*p).len = len;
}

/// `(mode, size)` of `inode`, zeros when unreadable.
#[inline(always)]
unsafe fn mode_size(inode: *const u8) -> (u16, u64) {
    let mode = bpf_probe_read_kernel::<u16>(inode.add(off!(INODE_I_MODE_OFFSET)) as *const u16).unwrap_or(0);
    let size = bpf_probe_read_kernel::<u64>(inode.add(off!(INODE_I_SIZE_OFFSET)) as *const u64).unwrap_or(0);
    (mode, size)
}

/// Lab PR 225, from `inode_rename` (`fim_watch::fim_rename_observe`): a
/// rename of a regular file to a new extension
/// ([`rename_shape`]) counts in its tgid's window ([`rename_step`]); the
/// crossing reports [`open_reason::MASS_RENAME`] once per window, the new
/// name as its path. Ransomware renames what it encrypted
/// (`a.pdf` → `a.pdf.locked`) one file after another; the burst is seen
/// wherever the files are, not only under a watched FIM directory. The
/// agent's own renames do not count.
///
/// A global BPF function, like [`nn_open_walk`]: verified once, on its own,
/// with plain values for arguments (the dentries, read from the context
/// array with [`raw_arg`]).
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_rename_burst(old_dentry: u64, new_dentry: u64) -> u64 {
    unsafe {
        let task = bpf_get_current_task();
        rename_burst(old_dentry as *const u8, new_dentry as *const u8, task);
        let _ = RENAME_TASK.remove(&task);
    }
    0
}

#[inline(always)]
unsafe fn rename_burst(old: *const u8, new: *const u8, task: u64) {
    if !armed() || old.is_null() || new.is_null() {
        return;
    }
    let inode = read_ptr(old.add(off!(DENTRY_D_INODE_OFFSET)));
    if inode.is_null() {
        return;
    }
    let (mode, _) = mode_size(inode);
    if mode & S_IFMT != S_IFREG {
        return;
    }
    let rt = match crate::task_scratch::make(&RENAME_TASK, &task) {
        Some(p) => p,
        None => {
            crate::drops::bump(northnarrow_common::ring_drops::ring_slot::OPEN_SENSOR);
            return;
        }
    };
    let sc = &mut (*rt).names;
    read_parts(old, &mut sc.old);
    read_parts(new, &mut sc.new);
    // Each extension scan, then the shape, in a global function of its
    // own, the results in map memory: inlined here together, the scans'
    // dot positions and the head comparisons multiplied the verifier's
    // paths past the 1M-instruction limit of 5.15 and 6.1 (lab PR 225;
    // KERNEL_COMPATIBILITY "Older verifiers", rule 11).
    let _ = nn_rename_ext(EXT_NEW as u64);
    let _ = nn_rename_ext(EXT_OLD as u64);
    let shape = nn_rename_shape() as u32;
    if shape == RENAME_OTHER {
        return;
    }
    if crate::fim_watch::caller_is_in_family() {
        return;
    }
    let (ext, src) = (
        core::ptr::read_volatile(&(*rt).ext[EXT_NEW]),
        core::ptr::read_volatile(&(*rt).ext[EXT_OLD]),
    );
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = bpf_ktime_get_ns();
    let appended = shape == RENAME_APPENDED;
    let crossed = match OPEN_RENAMES.get_ptr_mut(&tgid) {
        Some(w) => rename_step(&mut *w, ext, src, appended, now),
        None => {
            let _ = OPEN_RENAMES.insert(&tgid, &RenameWindow::fresh(now, ext, src, appended), 0);
            false
        }
    };
    if !crossed {
        return;
    }
    let (count, appended, sources) = match OPEN_RENAMES.get(&tgid) {
        Some(w) => (w.count, w.appended, w.sources),
        None => return,
    };
    let key = key_of(inode);
    emit(open_reason::MASS_RENAME, &key, new, appended, sources, count);
}

/// Lab PR 225: [`name_ext`] of the rename's new name (`slot`
/// [`EXT_NEW`]) or old name ([`EXT_OLD`]) in [`RENAME_SCRATCH`], written
/// to that slot of [`RENAME_EXT`]. A global function: verified once.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_rename_ext(slot: u64) -> u64 {
    unsafe {
        let rt = match RENAME_TASK.get_ptr_mut(&bpf_get_current_task()) {
            Some(p) => p,
            None => return 0,
        };
        let sc = &(*rt).names;
        let out = &mut (*rt).ext;
        if slot == EXT_NEW as u64 {
            let (h, len) = name_ext(&(*sc).new);
            core::ptr::write_volatile(&mut (*out)[EXT_NEW], h);
            core::ptr::write_volatile(&mut (*out)[EXT_NEW + 1], len as u64);
        } else {
            let (h, len) = name_ext(&(*sc).old);
            core::ptr::write_volatile(&mut (*out)[EXT_OLD], h);
            core::ptr::write_volatile(&mut (*out)[EXT_OLD + 1], len as u64);
        }
    }
    0
}

/// Lab PR 225: [`rename_shape_with`] of the names in [`RENAME_SCRATCH`]
/// and the extensions [`nn_rename_ext`] left in [`RENAME_EXT`]. A global
/// function: verified once.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_rename_shape() -> u64 {
    unsafe {
        let rt = match RENAME_TASK.get_ptr(&bpf_get_current_task()) {
            Some(p) => p,
            None => return RENAME_OTHER as u64,
        };
        let sc = &(*rt).names;
        let e = &(*rt).ext;
        let new_ext = (
            core::ptr::read_volatile(&(*e)[EXT_NEW]),
            core::ptr::read_volatile(&(*e)[EXT_NEW + 1]) as u32,
        );
        let old_ext = (
            core::ptr::read_volatile(&(*e)[EXT_OLD]),
            core::ptr::read_volatile(&(*e)[EXT_OLD + 1]) as u32,
        );
        rename_shape_with(&(*sc).old, &(*sc).new, new_ext, old_ext) as u64
    }
}

/// Lab PR 225, from `inode_unlink` (`fim_watch::fim_unlink_observe`): an
/// unlink of a regular file that destroys an original
/// ([`destroys_an_original`]: it holds data, or held it within the window
/// — lot 282, the review of #500; it was a file of at least 4 KiB) counts
/// in its tgid's window ([`unlink_step`]); the crossing reports
/// [`open_reason::MASS_UNLINK`] once per window. Ransomware that writes an
/// encrypted copy deletes the original. The agent's own unlinks do not
/// count. A global BPF function, as [`nn_rename_burst`].
///
/// Lot 282: an original destroyed. Also from `inode_rename`
/// (`fim_watch::fim_rename_observe`) with the rename's NEW dentry: a rename
/// onto the name of an existing regular file destroys that file (a
/// negative dentry, a name that did not exist, counts nothing). Each name
/// once per window ([`OPEN_DESTROY_SEEN`]: the parent dentry and the
/// name's hash); a name whose hash cannot be read counts every time.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_unlink_burst(dentry: u64) -> u64 {
    unsafe { unlink_burst(dentry as *const u8) };
    0
}

#[inline(always)]
unsafe fn unlink_burst(dentry: *const u8) {
    if !armed() || dentry.is_null() {
        return;
    }
    let inode = read_ptr(dentry.add(off!(DENTRY_D_INODE_OFFSET)));
    if inode.is_null() {
        return;
    }
    let (mode, size) = mode_size(inode);
    if mode & S_IFMT != S_IFREG {
        return;
    }
    if crate::fim_watch::caller_is_in_family() {
        return;
    }
    let key = key_of(inode);
    let parent = read_ptr(dentry.add(off!(DENTRY_D_PARENT_OFFSET)));
    // Lot 282, the re-review of #500: what the writes' count leaves out,
    // the destructions' does too — a pseudo-filesystem, `/run/systemd`,
    // the journal, the operator's extras, the destroyer's own runtime
    // directory ([`carved_class`]): a daemon's atomic replacements there are
    // no originals, and cost no map work.
    let cls = if parent.is_null() {
        None
    } else {
        parent_class(&key, parent)
    };
    let (bits, owner) = match cls {
        Some(c) => (c.bits, c.uid),
        None => (0, u32::MAX),
    };
    if cls.is_some() && carved_class(bits, owner, || loginuid()) {
        return;
    }
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = bpf_ktime_get_ns();
    // Lot 282, the review of #500 (C1): an empty file is an original only
    // if it held data within the window (emptied by a truncate first).
    if size == 0 && !destroys_an_original(0, OPEN_HAD_DATA.get(&key).copied(), now) {
        return;
    }
    // Lot 282: a file this process created within the window is its own
    // temporary file, no original.
    let made = OverwriteSeenKey {
        tgid,
        _pad: 0,
        dev: key.dev,
        ino: key.ino,
    };
    if created_in_window(OPEN_CREATED.get(&made).copied(), now) {
        return;
    }
    let hash_len =
        bpf_probe_read_kernel::<u64>(dentry.add(off!(DENTRY_D_NAME_OFFSET)) as *const u64).unwrap_or(0);
    if !parent.is_null() && hash_len != 0 {
        let start = match OPEN_UNLINKS.get(&tgid) {
            Some(w) => w.start_for(now),
            None => now,
        };
        let seen = DestroySeenKey {
            tgid,
            _pad: 0,
            parent: parent as u64,
            hash_len,
        };
        if !first_in_window(OPEN_DESTROY_SEEN.get(&seen).copied(), start) {
            return;
        }
        let _ = OPEN_DESTROY_SEEN.insert(&seen, &start, 0);
    }
    // Lot 283c: whose own data the originals destroyed in the window were.
    let own = own_of(bits, owner, dentry);
    let (count, summary) = match OPEN_UNLINKS.get_ptr_mut(&tgid) {
        Some(w) => {
            let c = unlink_step(&mut *w, now);
            (*w).own = own_after((*w).own, (*w).count == 1, true, own);
            (c, (*w).own)
        }
        None => {
            let w = UnlinkWindow {
                start_ns: now,
                count: 1,
                fired: 0,
                own,
                _pad: 0,
            };
            let _ = OPEN_UNLINKS.insert(&tgid, &w, 0);
            (0, own)
        }
    };
    if count == 0 {
        return;
    }
    emit(
        open_reason::MASS_UNLINK | ((summary & 0xFF) << open_reason::OWN_SHIFT),
        &key,
        dentry,
        0,
        0,
        count,
    );
}

/// Lot 282, the review of #500 (C1), from `inode_setattr`
/// (`fim_watch::fim_setattr_observe`): a regular file that holds data now,
/// before a truncate applies (its own setattr runs before it empties the
/// file), is remembered in [`OPEN_HAD_DATA`] — its unlink once emptied
/// still destroys an original. The re-review of #500 (cost): only a size
/// change (`ATTR_SIZE` in the `iattr`'s `ia_valid`: `truncate`,
/// `ftruncate`, an `O_TRUNC` open) — a chmod, a chown, a `touch` (a `tar
/// x` sets the times of every file) no longer pays a map insert, nor
/// evicts a truncated file's entry. A global BPF function, as
/// [`nn_unlink_burst`].
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_setattr_mark(dentry: u64, iattr: u64) -> u64 {
    unsafe { setattr_mark(dentry as *const u8, iattr as *const u8) };
    0
}

#[inline(always)]
unsafe fn setattr_mark(dentry: *const u8, iattr: *const u8) {
    if !armed() || dentry.is_null() || iattr.is_null() {
        return;
    }
    // `ia_valid` is `struct iattr`'s first member (an `unsigned int`) in
    // every kernel the agent supports, as it has been since 2.6.
    match bpf_probe_read_kernel::<u32>(iattr as *const u32) {
        Ok(v) if marks_had_data(v) => {}
        _ => return,
    }
    let inode = read_ptr(dentry.add(off!(DENTRY_D_INODE_OFFSET)));
    if inode.is_null() {
        return;
    }
    let (mode, size) = mode_size(inode);
    if mode & S_IFMT != S_IFREG || size == 0 {
        return;
    }
    let key = key_of(inode);
    let now = bpf_ktime_get_ns();
    let _ = OPEN_HAD_DATA.insert(&key, &now, 0);
}

/// Review 86: a file capability set by any route — `setcap`, a direct
/// `setxattr(2)`, `cp --preserve=xattr`, `tar --xattrs`, io_uring. On
/// `inode_post_setxattr`, so only a grant the kernel stored is reported,
/// and with the value after `cap_convert_nscap()`: a revision-3 value is a
/// capability namespaced to a user namespace whose root is not the
/// host's. The hook's signature, `(dentry, name, value, size, flags)`,
/// is the same on every supported kernel.
#[lsm(hook = "inode_post_setxattr")]
pub fn fim_file_cap_observe(ctx: LsmContext) -> i32 {
    if armed() {
        unsafe { try_file_cap(&ctx) };
    }
    0
}

/// `security.capability` with its NUL.
const XATTR_NAME_CAPS: [u8; 20] = *b"security.capability\0";

/// Argument `i` of the hook, read from the context's argument array
/// without the verifier's BTF typing: before 6.x it refuses a typed load
/// of a `void *` argument (`arg2 type UNKNOWN is not a struct`, AlmaLinux
/// 9's 5.14), and `value` is one.
#[inline(always)]
pub(crate) unsafe fn raw_arg(ctx: &LsmContext, i: usize) -> u64 {
    let args = ctx.as_ptr() as *const u64;
    bpf_probe_read_kernel(args.add(i)).unwrap_or(0)
}

#[inline(always)]
unsafe fn try_file_cap(ctx: &LsmContext) {
    let dentry: *const u8 = ctx.arg(0);
    let name = raw_arg(ctx, 1) as *const u8;
    let value = raw_arg(ctx, 2) as *const u8;
    let size = raw_arg(ctx, 3) as usize;
    if dentry.is_null() || name.is_null() || value.is_null() || size < 12 {
        return;
    }
    let mut n = [0u8; 20];
    if bpf_probe_read_kernel_str_bytes(name, &mut n).is_err() || n != XATTR_NAME_CAPS {
        return;
    }
    // struct vfs_cap_data: magic_etc, then {permitted, inheritable} for
    // the low and (revision >= 2) the high 32 capabilities.
    let mut head = [0u32; 3];
    if bpf_probe_read_kernel_buf(value, core::slice::from_raw_parts_mut(head.as_mut_ptr() as *mut u8, 12))
        .is_err()
    {
        return;
    }
    let mut high = 0u32;
    if size >= 16 {
        if let Ok(h) = bpf_probe_read_kernel::<u32>(value.add(12) as *const u32) {
            high = h;
        }
    }
    let inode = read_ptr(dentry.add(off!(DENTRY_D_INODE_OFFSET)));
    if inode.is_null() {
        return;
    }
    let key = key_of(inode);
    // The dentry goes to the global `nn_open_emit` as a plain value: the
    // hook's own argument is a BTF-typed pointer, which a global function
    // does not take (5.15: "R4 is not a scalar").
    let dentry_value = raw_arg(ctx, 0) as *const u8;
    emit(open_reason::FILE_CAP, &key, dentry_value, high, head[0], head[1]);
}

/// Lot 322 (the review of #546, F3): the walk's buffers an unlink or a
/// rename made ([`nn_open_walk`] from [`nn_unlink_burst`]), removed at the
/// end of `fim_watch::fim_unlink_observe` / `fim_rename_observe`.
#[inline(always)]
pub(crate) fn forget_task() {
    // SAFETY: a helper call with no argument.
    let task = unsafe { bpf_get_current_task() };
    let _ = OPEN_TASK.remove(&task);
}
