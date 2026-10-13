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
//! - write-opens counted per tgid ([`OPEN_WRITES`]).
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
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task,
        bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel,
        bpf_probe_read_kernel_buf, bpf_probe_read_kernel_str_bytes, gen,
    },
    macros::{lsm, map},
    maps::{Array, HashMap, LruHashMap, PerCpuArray, RingBuf},
    programs::LsmContext,
    EbpfContext,
};
use northnarrow_common::wire::open_sensor::{
    open_class::{
        CHILDREN_PROBE, CHILD_FILES, CLASSIFIED, DIRECT, DIR_HAS_FILES, FILE_CRITICAL,
        FILE_PERSIST, FILE_SENSITIVE, LEAF_CRED, LEAVES_CRED, SUBTREE, TREE_CARVEOUT, TREE_CRED,
        TREE_CRITICAL, TREE_HOME, TREE_PERSIST, TREE_RUNTIME,
    },
    open_reason, ChildRuleKey, DirClass, OpenRecordRaw, OpenWriteWindow, OPEN_CLASSIFY_DEPTH,
    OPEN_MASS_WRITE_MIN, OPEN_MASS_WRITE_WINDOW_NS, OPEN_NAME_LEN, OPEN_PATH_SLOTS,
    OPEN_PATH_SLOT_LEN, OPEN_SENSOR_ARMED,
};
use northnarrow_common::wire::{InodeKey, FIM_OP_OPENED};

use crate::btf_offsets::{
    DENTRY_D_INODE_OFFSET, DENTRY_D_NAME_OFFSET, DENTRY_D_PARENT_OFFSET, FILE_F_FLAGS_OFFSET,
    FILE_F_INODE_OFFSET, FILE_F_MODE_OFFSET, FILE_F_PATH_OFFSET, INODE_I_INO_OFFSET, INODE_I_MODE_OFFSET,
    INODE_I_SB_OFFSET, PATH_DENTRY_OFFSET, QSTR_NAME_OFFSET, SUPER_BLOCK_S_DEV_OFFSET,
    SUPER_BLOCK_S_MAGIC_OFFSET, TASK_STRUCT_LOGINUID_OFFSET,
};
use crate::read_repeat::ReadSeenKey;

const FMODE_WRITE: u32 = 0x2;
/// `FMODE_CREATED` (include/linux/fs.h, `1 << 20` since 4.19): this open
/// created the file. Set before `security_file_open` runs.
const FMODE_CREATED: u32 = 0x10_0000;
/// `OpenWriteWindow::fired` bits: the threshold already reported.
const FIRED_WRITES: u32 = 1;
const FIRED_OVERWRITES: u32 = 2;
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
pub static OPEN_RULES: HashMap<InodeKey, u32> = HashMap::with_max_entries(1024, 0);
/// `(registered directory, child name)` rules for paths missing when
/// userland registered the rules.
#[map]
pub static CHILD_RULES: HashMap<ChildRuleKey, u32> = HashMap::with_max_entries(256, 0);
/// Name rules, key = name ‖ parent name (all-zero parent = any parent):
/// directory names (`TREE_CRED`, `LEAVES_CRED`) and leaf names
/// (`LEAF_CRED`).
#[map]
pub static OPEN_NAME_RULES: HashMap<[u8; 2 * OPEN_NAME_LEN], u32> =
    HashMap::with_max_entries(64, 0);
/// Owner uid of each registered runtime directory (`TREE_RUNTIME`).
#[map]
pub static RUNTIME_UIDS: HashMap<InodeKey, u32> = HashMap::with_max_entries(256, 0);
/// Directory class cache, keyed by the directory's inode.
#[map]
pub static DIR_CLASS: LruHashMap<InodeKey, DirClass> = LruHashMap::with_max_entries(16384, 0);
/// Slot 0: the cache generation; a [`DirClass`] of another one is stale.
#[map]
pub static DIR_CLASS_GEN: Array<u32> = Array::with_max_entries(1, 0);
/// Per-tgid write-open windows (mass write).
#[map]
static OPEN_WRITES: LruHashMap<u32, OpenWriteWindow> = LruHashMap::with_max_entries(4096, 0);
/// Review 75: the last read-only report per (task, inode)
/// ([`crate::read_repeat`]).
#[map]
static OPEN_READ_SEEN: LruHashMap<ReadSeenKey, u64> = LruHashMap::with_max_entries(8192, 0);
/// Names and the child-rule key are built here, never on the stack:
/// [0..32) a name, [32..64) its parent's name, [64..112) a
/// `ChildRuleKey` (5.15 rule 4).
#[map]
static OPEN_SCRATCH: PerCpuArray<[u8; 128]> = PerCpuArray::with_max_entries(1, 0);
/// Bulk windows (per CPU), each read in one call: `struct file` at
/// [0, FILE_WIN) and the opened inode at [FILE_WIN, FILE_WIN + INODE_WIN).
/// A kernel read costs about 70 ns on the lab; one window replaces four
/// field reads (design §9.1).
const FILE_WIN: usize = 256;
const INODE_WIN: usize = 128;
#[map]
static OPEN_WIN: PerCpuArray<[u8; FILE_WIN + INODE_WIN]> = PerCpuArray::with_max_entries(1, 0);
/// Interesting opens only: a few per second on a busy host.
#[map]
pub static OPEN_SENSOR_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[inline(always)]
pub fn armed() -> bool {
    matches!(OPEN_SENSOR.get(0), Some(v) if *v == OPEN_SENSOR_ARMED)
}

#[inline(always)]
unsafe fn read_ptr(p: *const u8) -> *const u8 {
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
    let _ = gen::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 8, src as *const c_void);
    v.assume_init()
}

#[inline(always)]
unsafe fn peek_u32(src: *const u8) -> u32 {
    let mut v = core::mem::MaybeUninit::<u32>::uninit();
    let _ = gen::bpf_probe_read_kernel(v.as_mut_ptr() as *mut c_void, 4, src as *const c_void);
    v.assume_init()
}

/// `dentry->d_name.name` into `dst[..32]`, NUL-padded, the same way
/// (an unreadable name stays all zeros).
#[inline(always)]
unsafe fn peek_name(dentry: *const u8, name_off: usize, dst: *mut u8) {
    zero32(dst);
    let name = peek_u64(dentry.add(name_off)) as *const c_void;
    let _ = gen::bpf_probe_read_kernel_str(dst as *mut c_void, OPEN_NAME_LEN as u32, name);
}

/// `(dev, ino)` of `inode` as `stat()` reports it (review 55); dev 0 /
/// ino 0 when unreadable — a plain value, never an `Option` across the
/// inlined calls (5.15 rule 3).
#[inline(always)]
unsafe fn key_of(inode: *const u8) -> InodeKey {
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

/// The ancestor walk of [`dir_class`]: class bits in the low half, the
/// runtime directory's owner (or `u32::MAX`) in the high half.
///
/// A global BPF function (exported, never inlined, scalar arguments): the
/// verifier checks it once, on its own, and the sensor sees one unknown
/// return value. Inlined, its eight levels multiplied the states of the
/// rest of the program past the 5.15 verifier's million-instruction
/// budget. Every argument is a plain value, so any value is safe.
#[no_mangle]
#[inline(never)]
pub extern "C" fn nn_open_walk(dev: u64, ino: u64, dir: u64, dir_inode: u64) -> u64 {
    unsafe { walk(InodeKey { dev, ino }, dir as *const u8, dir_inode as *const u8) }
}

#[inline(always)]
unsafe fn walk(start: InodeKey, dir: *const u8, dir_inode: *const u8) -> u64 {
    let scratch = match OPEN_SCRATCH.get_ptr_mut(0) {
        Some(p) => p as *mut u8,
        None => return u64::from(u32::MAX) << 32,
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
    for level in 0..OPEN_CLASSIFY_DEPTH {
        // Level 0 is the directory itself (its children's rules apply);
        // above it only what a directory passes to its whole subtree.
        let keep = if level == 0 { DIRECT } else { SUBTREE };
        let r = rule(&key);
        bits |= r & keep;
        if r & TREE_RUNTIME != 0 {
            if let Some(u) = RUNTIME_UIDS.get(&key) {
                uid = *u;
            }
        }
        let up = peek_u64(d.add(o_parent)) as *const u8;
        if up.is_null() || up == d {
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
    (u64::from(uid) << 32) | u64::from(bits)
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

/// Count a write-open, and apart the write-opens of files that existed
/// (`overwrite`: no `FMODE_CREATED`; external audit POS-002). Returns the
/// [`open_reason`] bits this open adds — `MASS_WRITE` when the window's
/// write-opens cross the threshold, `MASS_OVERWRITE` when its overwrites
/// do, each once per window — and the window's count when it adds any.
#[inline(always)]
unsafe fn count_write(cls: &DirClass, overwrite: bool) -> (u32, u32) {
    if cls.bits & TREE_CARVEOUT != 0 {
        return (0, 0);
    }
    if cls.bits & TREE_RUNTIME != 0 && loginuid() == cls.uid {
        return (0, 0);
    }
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let now = bpf_ktime_get_ns();
    let over = overwrite as u32;
    match OPEN_WRITES.get_ptr_mut(&tgid) {
        Some(w) => {
            if now.saturating_sub((*w).start_ns) > OPEN_MASS_WRITE_WINDOW_NS {
                (*w).start_ns = now;
                (*w).count = 1;
                (*w).overwrites = over;
                (*w).fired = 0;
                (0, 0)
            } else {
                (*w).count += 1;
                (*w).overwrites += over;
                let mut bits = 0u32;
                if (*w).count >= OPEN_MASS_WRITE_MIN && (*w).fired & FIRED_WRITES == 0 {
                    (*w).fired |= FIRED_WRITES;
                    bits |= open_reason::MASS_WRITE;
                }
                if (*w).overwrites >= OPEN_MASS_WRITE_MIN && (*w).fired & FIRED_OVERWRITES == 0 {
                    (*w).fired |= FIRED_OVERWRITES;
                    bits |= open_reason::MASS_OVERWRITE;
                }
                if bits == 0 {
                    (0, 0)
                } else {
                    (bits, (*w).count)
                }
            }
        }
        None => {
            let w = OpenWriteWindow {
                start_ns: now,
                count: 1,
                fired: 0,
                overwrites: over,
                _pad: 0,
            };
            let _ = OPEN_WRITES.insert(&tgid, &w, 0);
            (0, 0)
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
/// one read of `struct file` and one of the inode.
#[inline(always)]
pub unsafe fn on_open(file: *const u8) {
    let w = match OPEN_WIN.get_ptr_mut(0) {
        Some(p) => p as *mut u8,
        None => core::ptr::null_mut(),
    };
    let inode = if w.is_null() {
        core::ptr::null()
    } else {
        read_windows(file, w)
    };
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
    observe(&key, watched, watched, mode, flags, dentry, regular);
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
    let scratch = match OPEN_SCRATCH.get_ptr_mut(0) {
        Some(p) => p as *mut u8,
        None => return,
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
                cred = kdbx_suffix(scratch);
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
    // Write-opens are counted before the family lookup, which then runs
    // only for an open that would emit: the agent's own writes count
    // under its own tgid and are dropped here when they cross the
    // threshold (once per window).
    let mut count = 0u32;
    if write && regular {
        let (bits, n) = count_write(&cls, mode & FMODE_CREATED == 0);
        reason |= bits;
        count = n;
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
    emit(reason, key, dentry, flags, mode, count);
}

/// `scratch[..32]` (a NUL-padded leaf name) ends in `.kdbx`: `.kdbx`
/// followed by the NUL, scanned at constant-bounded positions (no
/// `len - 5`, 5.15 rule 5). A name cut at 31 bytes cannot match.
#[inline(always)]
unsafe fn kdbx_suffix(scratch: *const u8) -> bool {
    let mut i = 1;
    while i + 5 < OPEN_NAME_LEN {
        if *scratch.add(i + 5) == 0 {
            return *scratch.add(i) == b'.'
                && *scratch.add(i + 1) == b'k'
                && *scratch.add(i + 2) == b'd'
                && *scratch.add(i + 3) == b'b'
                && *scratch.add(i + 4) == b'x';
        }
        i += 1;
    }
    false
}

/// The one emit site: identity, reason and the mount-relative path, plus
/// the key of the walk's top (a filesystem root) for userland's mount
/// lookup.
#[inline(always)]
unsafe fn emit(reason: u32, key: &InodeKey, dentry: *const u8, flags: u32, mode: u32, count: u32) {
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
    if let Ok(comm) = bpf_get_current_comm() {
        (*raw).comm = comm;
    }
    (*raw).dev = key.dev;
    (*raw).ino = key.ino;
    (*raw).flags = flags;
    (*raw).mode = mode;
    (*raw).reason = reason;
    (*raw).count = count;
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
unsafe fn raw_arg(ctx: &LsmContext, i: usize) -> u64 {
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
    emit(open_reason::FILE_CAP, &key, dentry, high, head[0], head[1]);
}
