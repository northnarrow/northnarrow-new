//! Lot 2.3a (stage S2, the kernel side): the decisions of the
//! trusted-installer window per process tree, as the eBPF programs take
//! them (`agent-ebpf/src/window_tree.rs`, `inode_protect.rs`,
//! `task_kill.rs`), kept here so that each is tested, and mutated, once.
//!
//! The design: `docs/design/ANTITAMPER_TRUST_MODEL.md`, "Trusted-installer
//! window per process tree" (sections 1, 3, 4, 5 and 6).
//!
//! * [`member_verdict`]: the lift test every hook asks through
//!   `override_active()` — the caller is a member of the window's current
//!   generation (`wire::FsGrantV2::lifts_for`: its entry, its start, no
//!   io_uring worker, the window open and its agent's heartbeat fresh),
//!   and it is not traced, not filtered by seccomp and in the initial
//!   namespaces; a member that fails the last three leaves the tree.
//! * [`exec_verdict`] and [`env_head_dangerous`]: the exec and mapping
//!   rule (D4), judged by the role's trust test (`exec_marks::code_verdict`,
//!   D10) plus the file's directory, and the loader and interpreter
//!   variables of the new environment.
//! * [`bdev_open_refusal`]: the block devices that back the agent's files.
//! * [`ancestor_rename_verdict`], [`window_lift_kept`]: the ancestors of
//!   the agent's paths and the key files (`wire::INODE_EXT`).
//! * [`denial_class`]: a refusal's context class (section 7).
//! * [`fatal_or_stop_by_default`]: the signals whose default action ends
//!   or stops a process (lot 330 a).
//!
//! Shared by the eBPF programs and the agent. NOT `std`-gated.

use crate::exec_marks::{CODE_TRUSTED, CodeFacts, code_verdict};
use crate::wire::{
    DENIAL_WINDOW_KEPT, DENIAL_WINDOW_NONE, DENIAL_WINDOW_OUTSIDER, FS_OP_BDEV_PASSTHROUGH,
    FS_OP_BDEV_PASSTHROUGH_NOTED, FS_OP_BDEV_READ, FS_OP_BDEV_WRITE, FS_OP_BDEV_WRITE_NOTED,
    FsGrantV2, INODE_EXT_DIR_KEPT, INODE_EXT_NO_RENAME, INODE_EXT_UNIT_LINKS,
    INODE_EXT_WINDOW_KEPT, KERNEL_READ_BLOCK_DEVICE, TreeMember,
};

// ── the lift test ───────────────────────────────────────────────────────

/// [`member_verdict`]: the window lifts the refusal for the caller.
pub const MEMBER_LIFT: u64 = 0;
/// [`member_verdict`]: no lift, and nothing to do — the caller has no entry
/// of the window's generation (an outsider, an entry of an earlier
/// window), the window is not open, or the caller is an io_uring worker
/// (`PF_IO_WORKER`: it runs requests any process sharing the ring queued;
/// its process stays a member).
pub const MEMBER_NONE: u64 = 1;
/// The reasons a member leaves the tree, from 2 ([`member_verdict`]'s
/// eviction, and the `detail`'s low byte of a `WINDOW_EVENT_EVICTION`
/// record). The member is traced (`task_struct.ptrace`), by any process:
/// an outsider's tracer, or a member's.
pub const EVICT_TRACED: u64 = 2;
/// It runs under a seccomp mode other than 0: a filter, a user-notify
/// supervisor in particular, can change what its calls do.
pub const EVICT_SECCOMP: u64 = 3;
/// It is outside the initial user or pid namespace.
pub const EVICT_NAMESPACE: u64 = 4;
/// A field of the per-lift test could not be read on this kernel: no lift
/// (a missing field is a missing hook), and the member leaves, signed.
pub const EVICT_UNREAD: u64 = 5;
/// It executed a file that fails the exec rule ([`exec_verdict`]); the
/// `detail`'s second byte is the reason (`exec_marks::CODE_*`,
/// [`CODE_UNSAFE_DIR`]).
pub const EVICT_EXEC: u64 = 6;
/// It mapped executable code that fails the rule (`mmap` with `PROT_EXEC`,
/// an `mprotect` that adds it; anonymous memory included).
pub const EVICT_MAP: u64 = 7;
/// It executed with a dangerous loader or interpreter variable in its
/// environment ([`env_head_dangerous`]), or one the bounded read could not
/// judge (longer than the bounds: counts as dangerous).
pub const EVICT_ENV: u64 = 8;
/// Not an eviction of a member: a member's child that the full members'
/// map could not take — it is outside the tree (fail closed), and the
/// record says why (the design's section 5, `left_outside_full`).
pub const EVICT_FULL: u64 = 9;

/// `WINDOW_EVENT_CLOSE`'s `detail`: the kernel closed the window when its
/// root's thread group died.
pub const CLOSE_ROOT_EXIT: u64 = 1;
/// The kernel closed the window when its root left the tree (evicted).
pub const CLOSE_ROOT_EVICTED: u64 = 2;

/// What the per-lift test reads of the calling task, besides its entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallerFacts {
    /// Every field below was read (their BTF slots resolved, the reads
    /// succeeded).
    pub read: bool,
    /// `task_struct.ptrace` is not 0.
    pub traced: bool,
    /// `task_struct.seccomp.mode`.
    pub seccomp_mode: u32,
    /// The task's credentials' user namespace is the initial one, and so
    /// is the pid namespace of its children.
    pub ns_initial: bool,
}

/// The grant in force: this boot's (`session`), numbered, before its
/// deadline — whatever its heartbeat says. While it is, the host-wide
/// grant lifts nothing (one window at a time), and a refusal is classed by
/// the window ([`denial_class`]). A grant whose agent's heartbeat is stale
/// lifts nothing either (`FsGrantV2::active`).
#[inline(always)]
pub const fn grant_in_force(g: &FsGrantV2, now_boot_ns: u64, session: u32) -> bool {
    g.nonce != 0 && g.nonce == session && g.generation != 0 && now_boot_ns < g.expires_boot_ns
}

/// Whether the kernel closed the window `generation` of session
/// `session`: `TREE_CLOSED`'s slot (`closed`: the session, the generation)
/// names it — written by the programs when the root's thread group dies or
/// the root leaves the tree, never by the agent but to empty it at its
/// start. A closed window lifts nothing, and the host-wide grant stays off
/// until the agent clears the slot ([`grant_in_force`]).
#[inline(always)]
pub const fn window_closed(closed: &[u64; 2], session: u32, generation: u64) -> bool {
    generation != 0 && closed[0] == session as u64 && closed[1] == generation
}

/// The lift test (the design's section 1, "the kernel's own test"):
/// [`MEMBER_LIFT`], [`MEMBER_NONE`], or the reason the member leaves the
/// tree (`EVICT_*`). The tree's membership is the grant's test
/// (`FsGrantV2::lifts_for`); a member is then judged on its own state at
/// this very call, so a tracer that attached after the grant's walk, a
/// filter installed since, or a namespace entered since takes the lift
/// away, and the member with it.
#[inline(always)]
pub fn member_verdict(
    grant: &FsGrantV2,
    member: Option<&TreeMember>,
    start_ticks: u64,
    io_worker: bool,
    caller: CallerFacts,
    now_boot_ns: u64,
    session: u32,
) -> u64 {
    if !grant.lifts_for(member, start_ticks, io_worker, now_boot_ns, session) {
        return MEMBER_NONE;
    }
    caller_state_verdict(caller)
}

/// The per-lift test's half on the caller's own state, for a member the
/// grant's test lifts for ([`member_verdict`]): [`MEMBER_LIFT`], or why it
/// leaves the tree. The eBPF lift asks it as a step of its own (the hooks'
/// stack chains).
#[inline(always)]
pub const fn caller_state_verdict(caller: CallerFacts) -> u64 {
    if !caller.read {
        return EVICT_UNREAD;
    }
    if caller.traced {
        return EVICT_TRACED;
    }
    if caller.seccomp_mode != 0 {
        return EVICT_SECCOMP;
    }
    if !caller.ns_initial {
        return EVICT_NAMESPACE;
    }
    MEMBER_LIFT
}

/// Whether a fork's child joins the tree: the forking process is a member
/// the window lifts for ([`MEMBER_LIFT`]), and the child is a new process,
/// not a thread (`CLONE_THREAD` shares its process's entry; one written for
/// it would overwrite the leader's).
#[inline(always)]
pub const fn child_joins(parent_verdict: u64, child_tgid: u32, parent_tgid: u32) -> bool {
    parent_verdict == MEMBER_LIFT && child_tgid != parent_tgid && child_tgid != 0
}

/// `TASK_NEW` (include/linux/sched.h): `sched_fork` sets it, and
/// `wake_up_new_task` clears it — a task that has not run yet.
pub const TASK_NEW: u32 = 0x0800;

/// The fork span's half of the members' guards (D7): a target with no
/// entry of the window is in the tree's span when a member's `task_alloc`
/// made it a member by its `task_struct` (`pending`, of the window's
/// generation), when it is still in `TASK_NEW` (`state`, its `__state`;
/// `None`: unread — the field is in the tree's manifest), or when its
/// `real_parent`'s process is a member of the window (`parent_member`: a
/// vfork child a full map left outside, a `CLONE_VM` child evicted before
/// its exec, which shares the member's memory). Guarded against outsiders,
/// never lifted.
#[inline(always)]
pub const fn in_tree_span(pending: bool, state: Option<u32>, parent_member: bool) -> bool {
    if pending || parent_member {
        return true;
    }
    match state {
        Some(s) => s & TASK_NEW != 0,
        None => false,
    }
}

/// Whether the members' entry of `tgid` is that very process's: its start
/// is the entry's (a reused tgid is another process, whose entry a member's
/// fork wrote over the stale one). The exit and the free remove an entry
/// only then.
#[inline(always)]
pub const fn entry_is_process(entry: &TreeMember, start_ticks: u64) -> bool {
    entry.start_ticks == start_ticks
}

/// Whether the process (`tgid`, `start_ticks`) is the window's root.
#[inline(always)]
pub const fn is_root(grant: &FsGrantV2, tgid: u32, start_ticks: u64) -> bool {
    grant.generation != 0 && grant.root_tgid == tgid && grant.root_start_ticks == start_ticks
}

// ── the exec and mapping rule (D4, judged by D10's test) ───────────────

/// [`exec_verdict`]'s reason beyond `exec_marks::code_verdict`'s: the file
/// lies in a directory writable by others or sticky (`/tmp`, `/var/tmp`,
/// `/dev/shm`, any other), or its directory could not be read.
pub const CODE_UNSAFE_DIR: u32 = 10;

/// `S_ISVTX`, `S_IWOTH` (include/uapi/linux/stat.h).
pub const S_ISVTX: u32 = 0o1000;
pub const S_IWOTH: u32 = 0o002;

/// The exec and mapping rule on one file (the design's section 4): the
/// role's trust test on the file (`exec_marks::code_verdict`: a regular
/// file, owned by root of the initial user namespace, writable by neither
/// its group nor others, with a name, on a local filesystem of the initial
/// user namespace, through a mount that is not idmapped), then its
/// directory's mode (`dir_mode`, `None` when it could not be read: fail
/// closed). [`CODE_TRUSTED`] keeps the member.
#[inline(always)]
pub const fn exec_verdict(facts: &CodeFacts, dir_mode: Option<u32>) -> u32 {
    let v = code_verdict(facts);
    if v != CODE_TRUSTED {
        return v;
    }
    match dir_mode {
        Some(m) if m & (S_ISVTX | S_IWOTH) == 0 => CODE_TRUSTED,
        _ => CODE_UNSAFE_DIR,
    }
}

/// The bounds of the environment's read at an exec: an environment with
/// more variables, more bytes, or a variable longer than these counts as
/// dangerous ([`EVICT_ENV`]).
pub const ENV_MAX_VARS: u32 = 128;
pub const ENV_MAX_BYTES: u64 = 32 * 1024;
pub const ENV_VAR_MAX: u32 = 4096;
/// The bytes of a variable's head the prefix test reads.
pub const ENV_HEAD: usize = 24;

/// How many [`DANGEROUS_ENV`] holds.
pub const ENV_PATTERNS: usize = 46;

/// The variables that change what a member's exec loads or interprets
/// before its own code: the loader's (`LD_*`), the shells' startup files
/// (`BASH_ENV`, `ENV`), the interpreters' module paths (`PYTHONPATH`,
/// `PYTHONSTARTUP`, `PERL5LIB`, `PERL5OPT`, `PERLLIB`), and the others the
/// units unset (`deploy/systemd/northnarrow-agent.service`,
/// `UnsetEnvironment=`). Each with its `=`, but for the two families
/// (`LD_`, `MALLOC_`). Lot 2.3a (the review of #647): bash's exported
/// functions (`BASH_FUNC_*`) and options (`SHELLOPTS`, `BASHOPTS`: `xtrace`
/// runs `PS4`'s expansions), apt's configuration (`APT_CONFIG`), the
/// option and module variables of node, ruby, java, lua, python and perl's
/// debugger, and git's that run a command or load a configuration
/// (`GIT_SSH_COMMAND`, `GIT_CONFIG_*`, …) — `LUA_INIT`, `LUA_PATH`,
/// `LUA_CPATH` and `BASH_FUNC_` as families.
pub const DANGEROUS_ENV: [&[u8]; ENV_PATTERNS] = [
    b"LD_",
    b"BASH_ENV=",
    b"ENV=",
    b"PYTHONPATH=",
    b"PYTHONSTARTUP=",
    b"PERL5LIB=",
    b"PERL5OPT=",
    b"PERLLIB=",
    b"GCONV_PATH=",
    b"GETCONF_DIR=",
    b"GLIBC_TUNABLES=",
    b"HOSTALIASES=",
    b"LOCALDOMAIN=",
    b"LOCPATH=",
    b"MALLOC_",
    b"NIS_PATH=",
    b"NLSPATH=",
    b"RESOLV_HOST_CONF=",
    b"RES_OPTIONS=",
    b"TZDIR=",
    b"BASH_FUNC_",
    b"SHELLOPTS=",
    b"BASHOPTS=",
    b"APT_CONFIG=",
    b"NODE_OPTIONS=",
    b"NODE_PATH=",
    b"RUBYOPT=",
    b"RUBYLIB=",
    b"JAVA_TOOL_OPTIONS=",
    b"_JAVA_OPTIONS=",
    b"JDK_JAVA_OPTIONS=",
    b"LUA_INIT",
    b"LUA_PATH",
    b"LUA_CPATH",
    b"PYTHONHOME=",
    b"PERL5DB=",
    b"GIT_EXEC_PATH=",
    b"GIT_SSH=",
    b"GIT_SSH_COMMAND=",
    b"GIT_ASKPASS=",
    b"GIT_PROXY_COMMAND=",
    b"GIT_EXTERNAL_DIFF=",
    b"GIT_CONFIG_COUNT=",
    b"GIT_CONFIG_PARAMETERS=",
    b"GIT_CONFIG_GLOBAL=",
    b"GIT_CONFIG_SYSTEM=",
];

/// A prefix as three little-endian words and their masks.
type Pattern = ([u64; 3], [u64; 3]);

const fn pattern(p: &[u8]) -> Pattern {
    let mut w = [0u64; 3];
    let mut m = [0u64; 3];
    let mut i = 0;
    while i < p.len() && i < ENV_HEAD {
        w[i / 8] |= (p[i] as u64) << ((i % 8) * 8);
        m[i / 8] |= 0xffu64 << ((i % 8) * 8);
        i += 1;
    }
    (w, m)
}

const PATTERNS: [Pattern; ENV_PATTERNS] = {
    let mut out = [([0u64; 3], [0u64; 3]); ENV_PATTERNS];
    let mut i = 0;
    while i < ENV_PATTERNS {
        out[i] = pattern(DANGEROUS_ENV[i]);
        i += 1;
    }
    out
};

#[inline(always)]
const fn hit(w: &[u64; 3], p: &Pattern) -> bool {
    w[0] & p.1[0] == p.0[0] && w[1] & p.1[1] == p.0[1] && w[2] & p.1[2] == p.0[2]
}

/// Whether a variable whose first [`ENV_HEAD`] bytes are `head` (as three
/// little-endian words; the bytes after the string's end zero) is one of
/// [`DANGEROUS_ENV`]. Unrolled, one immediate per word: the eBPF program
/// reads no table.
#[inline(always)]
pub const fn env_head_dangerous(head: &[u64; 3]) -> bool {
    hit(head, &PATTERNS[0])
        || hit(head, &PATTERNS[1])
        || hit(head, &PATTERNS[2])
        || hit(head, &PATTERNS[3])
        || hit(head, &PATTERNS[4])
        || hit(head, &PATTERNS[5])
        || hit(head, &PATTERNS[6])
        || hit(head, &PATTERNS[7])
        || hit(head, &PATTERNS[8])
        || hit(head, &PATTERNS[9])
        || hit(head, &PATTERNS[10])
        || hit(head, &PATTERNS[11])
        || hit(head, &PATTERNS[12])
        || hit(head, &PATTERNS[13])
        || hit(head, &PATTERNS[14])
        || hit(head, &PATTERNS[15])
        || hit(head, &PATTERNS[16])
        || hit(head, &PATTERNS[17])
        || hit(head, &PATTERNS[18])
        || hit(head, &PATTERNS[19])
        || hit(head, &PATTERNS[20])
        || hit(head, &PATTERNS[21])
        || hit(head, &PATTERNS[22])
        || hit(head, &PATTERNS[23])
        || hit(head, &PATTERNS[24])
        || hit(head, &PATTERNS[25])
        || hit(head, &PATTERNS[26])
        || hit(head, &PATTERNS[27])
        || hit(head, &PATTERNS[28])
        || hit(head, &PATTERNS[29])
        || hit(head, &PATTERNS[30])
        || hit(head, &PATTERNS[31])
        || hit(head, &PATTERNS[32])
        || hit(head, &PATTERNS[33])
        || hit(head, &PATTERNS[34])
        || hit(head, &PATTERNS[35])
        || hit(head, &PATTERNS[36])
        || hit(head, &PATTERNS[37])
        || hit(head, &PATTERNS[38])
        || hit(head, &PATTERNS[39])
        || hit(head, &PATTERNS[40])
        || hit(head, &PATTERNS[41])
        || hit(head, &PATTERNS[42])
        || hit(head, &PATTERNS[43])
        || hit(head, &PATTERNS[44])
        || hit(head, &PATTERNS[45])
}

/// [`env_head_dangerous`] of a byte string (the tests', and the agent's).
pub fn env_var_dangerous(var: &[u8]) -> bool {
    let mut w = [0u64; 3];
    for (i, b) in var.iter().take(ENV_HEAD).enumerate() {
        w[i / 8] |= u64::from(*b) << ((i % 8) * 8);
    }
    env_head_dangerous(&w)
}

/// The environment's bounds ([`ENV_MAX_VARS`], [`ENV_MAX_BYTES`],
/// [`ENV_VAR_MAX`]): `bytes` its size, `vars` the variables read before
/// the end, `longest` the longest one read (with its NUL), `ended` whether
/// the read reached the end of the region. An environment the read could
/// not cover counts as dangerous.
pub const fn env_within_bounds(bytes: u64, vars: u32, longest: u32, ended: bool) -> bool {
    bytes <= ENV_MAX_BYTES && vars <= ENV_MAX_VARS && longest < ENV_VAR_MAX && ended
}

// ── the block devices ──────────────────────────────────────

/// `PROTECTED_BDEVS`' value: the block device backs a filesystem the
/// agent's files live on (or holds it: the whole disk of a partition, a
/// device under a device-mapper or md device).
pub const BDEV_BACKS_PROTECTED: u8 = 1;
/// Lot 2.3a (the review of #647): `PROTECTED_BDEVS`' value for a character
/// device that reaches such a disk's blocks — its SCSI generic node
/// (`/dev/sg*`), its bsg node, its NVMe generic node (`/dev/ngXnY`) or
/// its NVMe controller (`/dev/nvmeX`). The map is keyed by the device
/// number alone: a block and a character device of one number share the
/// entry, each matching its own bit ([`bdev_entry_bit`]).
pub const BDEV_PASSTHROUGH_NODE: u8 = 2;

/// The entry bit an inode matches: [`BDEV_BACKS_PROTECTED`] for a block
/// device, [`BDEV_PASSTHROUGH_NODE`] for a character device.
#[inline(always)]
pub const fn bdev_entry_bit(block: bool) -> u8 {
    if block {
        BDEV_BACKS_PROTECTED
    } else {
        BDEV_PASSTHROUGH_NODE
    }
}

/// A raw access judged by [`bdev_verdict`]: a read-open, a write-open, a
/// passthrough command (`SG_IO`, an NVMe command: [`is_passthrough_ioctl`]).
pub const BDEV_ACCESS_READ: u8 = 0;
pub const BDEV_ACCESS_WRITE: u8 = 1;
pub const BDEV_ACCESS_PASSTHROUGH: u8 = 2;

/// `SG_IO`, `SCSI_IOCTL_SEND_COMMAND` (include/scsi/sg.h,
/// include/uapi/linux/../scsi/scsi_ioctl.h).
pub const SG_IO: u32 = 0x2285;
pub const SCSI_IOCTL_SEND_COMMAND: u32 = 1;
/// The NVMe ioctls' type (`'N'`) and the numbers of those that carry a
/// command (include/uapi/linux/nvme_ioctl.h: `ADMIN_CMD` 0x41,
/// `SUBMIT_IO` 0x42, `IO_CMD` 0x43, `ADMIN64_CMD` 0x47, `IO64_CMD` 0x48,
/// `IO64_CMD_VEC` 0x49), whatever the size their encoding carries.
pub const NVME_IOCTL_TYPE: u32 = 0x4E;

/// Whether `cmd` sends a device a command of its own: SCSI's `SG_IO` and
/// `SCSI_IOCTL_SEND_COMMAND` (a CAP_SYS_RAWIO caller's, whatever the open
/// mode), or one of NVMe's command ioctls (a CAP_SYS_ADMIN caller's, on a
/// read-only descriptor too) — each a write of any block, past the open's
/// mode.
#[inline(always)]
pub const fn is_passthrough_ioctl(cmd: u32) -> bool {
    if cmd == SG_IO || cmd == SCSI_IOCTL_SEND_COMMAND {
        return true;
    }
    (cmd >> 8) & 0xff == NVME_IOCTL_TYPE
        && matches!(cmd & 0xff, 0x41 | 0x42 | 0x43 | 0x47 | 0x48 | 0x49)
}

/// The verdict on a raw `access` ([`BDEV_ACCESS_READ`], `_WRITE`,
/// `_PASSTHROUGH`) to a device whose `PROTECTED_BDEVS` entry is `entry`
/// (`None`: not one of them), matched on `bit` ([`bdev_entry_bit`]), by a
/// caller outside the agent's family the window does not lift for
/// (`lifted`): the record's operation, 0 when nothing is recorded.
///
/// The decision of the review of #647 (a self-DoS otherwise: grub-install
/// on a BIOS host, LVM metadata, cryptsetup, tune2fs and resize2fs write
/// the disk of a mounted root): by default a write-open or a passthrough
/// command is let through and RECORDED ([`FS_OP_BDEV_WRITE_NOTED`],
/// [`FS_OP_BDEV_PASSTHROUGH_NOTED`], High), a read-open is nothing; under
/// the kernel-read option's block-device class (`kread_mask`:
/// `kernel-read-refuse`, the operator's strict choice) each is REFUSED
/// ([`FS_OP_BDEV_WRITE`], [`FS_OP_BDEV_PASSTHROUGH`], [`FS_OP_BDEV_READ`]).
/// A character node is judged at its write-open and its commands, never
/// at a read-open.
#[inline(always)]
pub const fn bdev_verdict(
    entry: Option<u8>,
    bit: u8,
    access: u8,
    kread_mask: u32,
    lifted: bool,
) -> u8 {
    let matched = match entry {
        Some(f) => f & bit != 0,
        None => false,
    };
    if !matched || lifted {
        return 0;
    }
    let strict = kread_mask & KERNEL_READ_BLOCK_DEVICE != 0;
    match access {
        BDEV_ACCESS_WRITE => {
            if strict {
                FS_OP_BDEV_WRITE
            } else {
                FS_OP_BDEV_WRITE_NOTED
            }
        }
        BDEV_ACCESS_PASSTHROUGH => {
            if strict {
                FS_OP_BDEV_PASSTHROUGH
            } else {
                FS_OP_BDEV_PASSTHROUGH_NOTED
            }
        }
        _ => {
            if strict && bit == BDEV_BACKS_PROTECTED {
                FS_OP_BDEV_READ
            } else {
                0
            }
        }
    }
}

/// Whether [`bdev_verdict`]'s operation refuses the access (the others
/// are recorded and let through).
#[inline(always)]
pub const fn bdev_refuses(op: u8) -> bool {
    matches!(
        op,
        FS_OP_BDEV_WRITE | FS_OP_BDEV_PASSTHROUGH | FS_OP_BDEV_READ
    )
}

// ── the ancestors and the key files (the ancestors, the key files) ────────────────────

/// Whether the rename or exchange of an inode whose `INODE_EXT` word is
/// `ext` (`None`: no entry) is refused for its own sake: an ancestor of
/// the agent's paths ([`INODE_EXT_NO_RENAME`]), for a caller outside the
/// agent's family (`family`), unless the window lifts it for the caller
/// (`lifted`) and the inode is not one the window keeps
/// ([`INODE_EXT_DIR_KEPT`]: the key files' directory and its ancestors).
#[inline(always)]
pub const fn ancestor_rename_verdict(ext: Option<u8>, lifted: bool, family: bool) -> bool {
    let ext = match ext {
        Some(e) => e,
        None => return false,
    };
    if ext & INODE_EXT_NO_RENAME == 0 || family {
        return false;
    }
    !lifted || ext & INODE_EXT_DIR_KEPT != 0
}

/// Whether the window keeps refusing what it lifts on an inode whose
/// `INODE_EXT` word is `ext` (the key files: `admin.pub`, the agent's signing
/// key): no window lifts their write, rename, removal or the key's read,
/// for anyone but the agent's family (who is let through before). The key
/// files' directory carries [`INODE_EXT_DIR_KEPT`] instead: a window keeps
/// its own rename, never what is done to its entries.
#[inline(always)]
pub const fn window_lift_kept(ext: Option<u8>) -> bool {
    match ext {
        Some(e) => e & INODE_EXT_WINDOW_KEPT != 0,
        None => false,
    }
}

/// Lot 2.3a (the review of #647): the names of our units' enablement
/// links (`nn_linux`'s `ENABLEMENT_LINK_NAMES`, the same list).
pub const UNIT_LINK_NAMES: [&[u8]; 2] = [
    b"northnarrow-agent.service",
    b"northnarrow-watchdog.service",
];

/// A name of at most 31 bytes as four little-endian words, zero after its
/// end (as `bpf_probe_read_kernel_str` leaves a zeroed buffer).
pub const fn name_words4(n: &[u8]) -> [u64; 4] {
    let mut w = [0u64; 4];
    let mut i = 0;
    while i < n.len() && i < 31 {
        w[i / 8] |= (n[i] as u64) << ((i % 8) * 8);
        i += 1;
    }
    w
}

const UNIT_LINK_WORDS: [[u64; 4]; 2] = [
    name_words4(UNIT_LINK_NAMES[0]),
    name_words4(UNIT_LINK_NAMES[1]),
];

#[inline(always)]
const fn words_eq(a: &[u64; 4], b: &[u64; 4]) -> bool {
    a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3]
}

/// Whether a directory entry's name (`w`: [`name_words4`]) is one of
/// [`UNIT_LINK_NAMES`].
#[inline(always)]
pub const fn is_unit_link_name(w: &[u64; 4]) -> bool {
    words_eq(w, &UNIT_LINK_WORDS[0]) || words_eq(w, &UNIT_LINK_WORDS[1])
}

/// Whether the removal or the rename (in or out) of an entry named
/// `ours` ([`is_unit_link_name`]) in a directory whose `INODE_EXT` word is
/// `ext` is refused: a directory of our units' links
/// ([`INODE_EXT_UNIT_LINKS`]), for a caller outside the agent's family
/// (`family`) the window does not lift for (`lifted`) — the enablement
/// links' MUTATE protection, by name.
#[inline(always)]
pub const fn unit_link_verdict(ext: Option<u8>, ours: bool, lifted: bool, family: bool) -> bool {
    let ext = match ext {
        Some(e) => e,
        None => return false,
    };
    ext & INODE_EXT_UNIT_LINKS != 0 && ours && !lifted && !family
}

// ── records ────────────────────────────────────────────────────────────

/// A refusal's context class (the design's section 7): no tree window in
/// force ([`DENIAL_WINDOW_NONE`]); one in force, and the caller outside its
/// tree ([`DENIAL_WINDOW_OUTSIDER`], High, never lower) or a member it
/// keeps the refusal for ([`DENIAL_WINDOW_KEPT`]).
#[inline(always)]
pub const fn denial_class(tree_in_force: bool, member: bool) -> u8 {
    if !tree_in_force {
        DENIAL_WINDOW_NONE
    } else if member {
        DENIAL_WINDOW_KEPT
    } else {
        DENIAL_WINDOW_OUTSIDER
    }
}

/// Whether a record of `operation` takes a window class
/// ([`denial_class`]; an outsider's also a window record, High): a refusal
/// only. A record of what was let through (`wire::is_let_through`: a fatal
/// signal to the agent's family, a mount or an unmount noted, a block
/// device's raw write recorded) is no "outsider refused".
#[inline(always)]
pub const fn window_classes(operation: u8) -> bool {
    !crate::wire::is_let_through(operation)
}

// ── a new instance (task_kill) ─────────────────────────────────────────

/// How long a process running the agent's or the watchdog's binary is
/// protected by `task_kill` before it registers, at most: until it
/// registers in the pinned `PROTECTED_PIDS` (into its predecessor's map,
/// before its bootstraps: a second or two) or exits, capped at 60 s (the
/// review of #647: a fixed 10 s did not hold under load — one vCPU, a
/// real-time spinner, a slow verifier — and left a start killable).
pub const NEW_INSTANCE_NS: u64 = 60_000_000_000;

/// Whether `task_kill` protects a target that is not a protected pid: it
/// runs one of our binaries (`role`: `OWN_EXE_INODES`' role of its
/// executable, 0 for none), it is not that role's live holder (`holder`:
/// the role's `ROLE_TGIDS` slot; `tgid`: the target's), it was started
/// for its role (`for_role`: systemd's start of the role's unit — a child
/// of PID 1 in that unit's own cgroup, lot 374's test), and it has not
/// registered yet within [`NEW_INSTANCE_NS`] (`age_ns`; `None`: its start
/// unread, protected). A holder that is no longer a protected pid, a
/// process run by hand or by a test or by `install.sh` (not systemd's
/// start of the unit), and one past the cap, are signalled as before; the
/// window lifts the protection for the processes it lifts. The new
/// binary's inode after an upgrade (`OWN_EXE_INODES`) is marked by the
/// new instance's own start, re-marked by the upgrade flow in lot 2.4.
#[inline(always)]
pub const fn new_instance_protected(
    role: u8,
    holder: Option<u32>,
    tgid: u32,
    for_role: bool,
    age_ns: Option<u64>,
) -> bool {
    if role == 0 || !for_role {
        return false;
    }
    if matches!(holder, Some(h) if h == tgid) {
        return false;
    }
    match age_ns {
        Some(a) => a < NEW_INSTANCE_NS,
        None => true,
    }
}

// ── the fatal signals (lot 330 a) ──────────────────────────────────────

/// Whether `sig`'s default action ends the process (terminate, or core
/// dump) or stops it: every signal but `SIGCHLD`, `SIGCONT`, `SIGURG` and
/// `SIGWINCH` (ignored or continue by default), and 0 (no signal). The
/// real-time signals (32 to 64) terminate by default.
#[inline(always)]
pub const fn fatal_or_stop_by_default(sig: i32) -> bool {
    matches!(sig, 1..=16 | 19..=22 | 24..=27 | 29..=64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec_marks::{CODE_NOT_ROOT, CODE_WRITABLE, S_IFREG};
    use crate::wire::{TREE_MEMBER_ROOT, WINDOW_AGENT_GRACE_NS};

    /// A session nonce no literal names (CodeQL
    /// `rust/hard-coded-cryptographic-value`, as lot 2.2's `test_nonce`).
    fn test_nonce() -> u32 {
        let pid = std::process::id();
        pid.rotate_left(7) ^ pid
    }
    const NOW: u64 = 1_000_000_000_000;

    fn grant() -> FsGrantV2 {
        FsGrantV2 {
            nonce: test_nonce(),
            root_tgid: 4242,
            generation: 7,
            expires_boot_ns: NOW + 60_000_000_000,
            root_start_ticks: 1234,
            heartbeat_boot_ns: NOW - 1_000_000_000,
            first_grant_boot_ns: NOW - 2_000_000_000,
        }
    }

    fn member(start: u64, generation: u64) -> TreeMember {
        TreeMember {
            start_ticks: start,
            generation,
            flags: 0,
            _pad: 0,
        }
    }

    const CLEAN: CallerFacts = CallerFacts {
        read: true,
        traced: false,
        seccomp_mode: 0,
        ns_initial: true,
    };

    #[test]
    fn a_member_of_the_generation_is_lifted() {
        let g = grant();
        let m = member(99, 7);
        assert_eq!(
            member_verdict(&g, Some(&m), 99, false, CLEAN, NOW, test_nonce()),
            MEMBER_LIFT
        );
    }

    #[test]
    fn an_outsider_or_a_stale_entry_is_not_lifted_nor_evicted() {
        let g = grant();
        assert_eq!(
            member_verdict(&g, None, 99, false, CLEAN, NOW, test_nonce()),
            MEMBER_NONE
        );
        // an entry of an earlier window
        let old = member(99, 6);
        assert_eq!(
            member_verdict(&g, Some(&old), 99, false, CLEAN, NOW, test_nonce()),
            MEMBER_NONE
        );
        // a reused tgid: another start
        let m = member(99, 7);
        assert_eq!(
            member_verdict(&g, Some(&m), 100, false, CLEAN, NOW, test_nonce()),
            MEMBER_NONE
        );
        // an io_uring worker of a member: no lift, its process stays
        assert_eq!(
            member_verdict(&g, Some(&m), 99, true, CLEAN, NOW, test_nonce()),
            MEMBER_NONE
        );
        // another boot's session
        assert_eq!(
            member_verdict(
                &g,
                Some(&m),
                99,
                false,
                CLEAN,
                NOW,
                test_nonce().wrapping_add(1)
            ),
            MEMBER_NONE
        );
        // past the deadline
        assert_eq!(
            member_verdict(
                &g,
                Some(&m),
                99,
                false,
                CLEAN,
                g.expires_boot_ns,
                test_nonce()
            ),
            MEMBER_NONE
        );
        // the agent's heartbeat stale: the window closed itself
        let late = g.heartbeat_boot_ns + WINDOW_AGENT_GRACE_NS;
        let mut g2 = g;
        g2.expires_boot_ns = late + 1;
        assert_eq!(
            member_verdict(&g2, Some(&m), 99, false, CLEAN, late, test_nonce()),
            MEMBER_NONE
        );
    }

    #[test]
    fn a_traced_filtered_or_namespaced_member_leaves() {
        let g = grant();
        let m = member(99, 7);
        let traced = CallerFacts {
            traced: true,
            ..CLEAN
        };
        assert_eq!(
            member_verdict(&g, Some(&m), 99, false, traced, NOW, test_nonce()),
            EVICT_TRACED
        );
        let filtered = CallerFacts {
            seccomp_mode: 2,
            ..CLEAN
        };
        assert_eq!(
            member_verdict(&g, Some(&m), 99, false, filtered, NOW, test_nonce()),
            EVICT_SECCOMP
        );
        let strict = CallerFacts {
            seccomp_mode: 1,
            ..CLEAN
        };
        assert_eq!(
            member_verdict(&g, Some(&m), 99, false, strict, NOW, test_nonce()),
            EVICT_SECCOMP
        );
        let ns = CallerFacts {
            ns_initial: false,
            ..CLEAN
        };
        assert_eq!(
            member_verdict(&g, Some(&m), 99, false, ns, NOW, test_nonce()),
            EVICT_NAMESPACE
        );
        let unread = CallerFacts {
            read: false,
            ..CLEAN
        };
        assert_eq!(
            member_verdict(&g, Some(&m), 99, false, unread, NOW, test_nonce()),
            EVICT_UNREAD
        );
        // an outsider's facts never evict anything
        assert_eq!(
            member_verdict(&g, None, 99, false, traced, NOW, test_nonce()),
            MEMBER_NONE
        );
    }

    #[test]
    fn the_reasons_are_distinct_and_above_the_verdicts() {
        let r = [
            EVICT_TRACED,
            EVICT_SECCOMP,
            EVICT_NAMESPACE,
            EVICT_UNREAD,
            EVICT_EXEC,
            EVICT_MAP,
            EVICT_ENV,
            EVICT_FULL,
        ];
        for (i, a) in r.iter().enumerate() {
            assert!(*a > MEMBER_NONE && *a < 0x100);
            for b in &r[i + 1..] {
                assert_ne!(a, b);
            }
        }
        assert_ne!(MEMBER_LIFT, MEMBER_NONE);
    }

    #[test]
    fn grant_in_force_ignores_the_heartbeat_only() {
        let g = grant();
        assert!(grant_in_force(&g, NOW, test_nonce()));
        assert!(!grant_in_force(&g, NOW, test_nonce().wrapping_add(1)));
        assert!(!grant_in_force(&g, g.expires_boot_ns, test_nonce()));
        assert!(grant_in_force(&g, g.expires_boot_ns - 1, test_nonce()));
        let none = FsGrantV2 { generation: 0, ..g };
        assert!(!grant_in_force(&none, NOW, test_nonce()));
        let unset = FsGrantV2 {
            nonce: FsGrantV2::default().nonce,
            ..g
        };
        assert!(!grant_in_force(&unset, NOW, 0));
        // a stale heartbeat: still in force (the host-wide grant stays off)
        let stale = FsGrantV2 {
            heartbeat_boot_ns: 0,
            ..g
        };
        assert!(grant_in_force(&stale, NOW, test_nonce()));
        assert!(!stale.active(NOW, test_nonce()));
    }

    #[test]
    fn a_window_the_kernel_closed() {
        assert!(window_closed(
            &[u64::from(test_nonce()), 7],
            test_nonce(),
            7
        ));
        assert!(!window_closed(
            &[u64::from(test_nonce()), 6],
            test_nonce(),
            7
        ));
        assert!(!window_closed(
            &[u64::from(test_nonce()) + 1, 7],
            test_nonce(),
            7
        ));
        assert!(!window_closed(&[0, 0], 0, 0));
        assert!(!window_closed(
            &[u64::from(test_nonce()), 0],
            test_nonce(),
            0
        ));
    }

    #[test]
    fn a_child_joins_only_from_a_lifted_member_and_not_as_a_thread() {
        assert!(child_joins(MEMBER_LIFT, 11, 10));
        assert!(!child_joins(MEMBER_NONE, 11, 10));
        assert!(!child_joins(EVICT_TRACED, 11, 10));
        assert!(!child_joins(MEMBER_LIFT, 10, 10));
        assert!(!child_joins(MEMBER_LIFT, 0, 10));
    }

    #[test]
    fn an_entry_is_removed_only_for_its_own_process() {
        let m = member(500, 7);
        assert!(entry_is_process(&m, 500));
        assert!(!entry_is_process(&m, 501));
    }

    #[test]
    fn the_root_is_its_tgid_and_its_start() {
        let g = grant();
        assert!(is_root(&g, 4242, 1234));
        assert!(!is_root(&g, 4242, 1235));
        assert!(!is_root(&g, 4243, 1234));
        let none = FsGrantV2 { generation: 0, ..g };
        assert!(!is_root(&none, 4242, 1234));
        let _ = TREE_MEMBER_ROOT;
    }

    fn file(mode: u32, uid: u32) -> CodeFacts {
        CodeFacts {
            mode,
            uid,
            nlink: Some(1),
            magic: 0xef53,
            virtiofs: false,
            foreign_sb: false,
            idmapped: false,
        }
    }

    #[test]
    fn the_exec_rule_judges_the_file_then_its_directory() {
        let sys = file(S_IFREG | 0o755, 0);
        assert_eq!(exec_verdict(&sys, Some(0o040755)), CODE_TRUSTED);
        // /tmp: sticky and writable by others
        assert_eq!(exec_verdict(&sys, Some(0o041777)), CODE_UNSAFE_DIR);
        // sticky only, or writable by others only
        assert_eq!(exec_verdict(&sys, Some(0o041755)), CODE_UNSAFE_DIR);
        assert_eq!(exec_verdict(&sys, Some(0o040757)), CODE_UNSAFE_DIR);
        // a group-writable directory is the file test's business, not this one
        assert_eq!(exec_verdict(&sys, Some(0o040775)), CODE_TRUSTED);
        // unread: fail closed
        assert_eq!(exec_verdict(&sys, None), CODE_UNSAFE_DIR);
        // the file's own reasons first
        assert_eq!(
            exec_verdict(&file(S_IFREG | 0o755, 1000), Some(0o040755)),
            CODE_NOT_ROOT
        );
        assert_eq!(
            exec_verdict(&file(S_IFREG | 0o777, 0), Some(0o041777)),
            CODE_WRITABLE
        );
        const { assert!(CODE_UNSAFE_DIR > crate::exec_marks::CODE_IDMAPPED) };
    }

    #[test]
    fn the_dangerous_variables_are_matched_by_their_names() {
        for v in [
            &b"LD_PRELOAD=/tmp/x.so"[..],
            b"LD_LIBRARY_PATH=/opt",
            b"LD_AUDIT=a",
            b"BASH_ENV=/tmp/rc",
            b"ENV=/tmp/rc",
            b"PYTHONPATH=/tmp",
            b"PYTHONSTARTUP=/tmp/s.py",
            b"PERL5LIB=/tmp",
            b"PERL5OPT=-Mx",
            b"PERLLIB=/tmp",
            b"GCONV_PATH=/tmp",
            b"GETCONF_DIR=/tmp",
            b"GLIBC_TUNABLES=glibc.malloc.x=1",
            b"HOSTALIASES=/tmp/h",
            b"LOCALDOMAIN=x",
            b"LOCPATH=/tmp",
            b"MALLOC_ARENA_MAX=2",
            b"MALLOC_CHECK_=3",
            b"NIS_PATH=x",
            b"NLSPATH=/tmp",
            b"RESOLV_HOST_CONF=/tmp/r",
            b"RES_OPTIONS=debug",
            b"TZDIR=/tmp",
            b"ENV=",
        ] {
            assert!(env_var_dangerous(v), "{}", String::from_utf8_lossy(v));
        }
        for v in [
            &b"PATH=/usr/bin"[..],
            b"HOME=/root",
            b"LANG=C.UTF-8",
            b"ENVIRONMENT=prod",
            b"LD=ld.gold",
            b"XLD_PRELOAD=x",
            b"PYTHONPATHS=x",
            b"PYTHONDONTWRITEBYTECODE=1",
            b"TZ=UTC",
            b"MALLOC=x",
            b"BASH_ENVX=1",
            b"RESOLV_HOST_CONFX=1",
            b"DEBIAN_FRONTEND=noninteractive",
            b"",
        ] {
            assert!(!env_var_dangerous(v), "{}", String::from_utf8_lossy(v));
        }
    }

    #[test]
    fn every_dangerous_name_fits_the_head() {
        for p in DANGEROUS_ENV {
            assert!(p.len() <= ENV_HEAD);
            assert!(env_var_dangerous(p));
            // one byte short is not the name (the families aside)
            let short = &p[..p.len() - 1];
            if p.ends_with(b"=") {
                assert!(!env_var_dangerous(short), "{}", String::from_utf8_lossy(p));
            }
        }
    }

    #[test]
    fn the_environment_bounds() {
        assert!(env_within_bounds(2048, 40, 300, true));
        assert!(env_within_bounds(
            ENV_MAX_BYTES,
            ENV_MAX_VARS,
            ENV_VAR_MAX - 1,
            true
        ));
        assert!(!env_within_bounds(ENV_MAX_BYTES + 1, 40, 300, true));
        assert!(!env_within_bounds(2048, ENV_MAX_VARS + 1, 300, true));
        assert!(!env_within_bounds(2048, 40, ENV_VAR_MAX, true));
        assert!(!env_within_bounds(2048, 40, 300, false));
    }

    #[test]
    fn a_protected_block_device_records_foreign_writes_and_refuses_them_under_the_option() {
        let p = Some(BDEV_BACKS_PROTECTED);
        let b = BDEV_BACKS_PROTECTED;
        let strict = KERNEL_READ_BLOCK_DEVICE;
        // by default: a write-open and a passthrough command recorded, let through
        assert_eq!(
            bdev_verdict(p, b, BDEV_ACCESS_WRITE, 0, false),
            FS_OP_BDEV_WRITE_NOTED
        );
        assert_eq!(
            bdev_verdict(p, b, BDEV_ACCESS_PASSTHROUGH, 0, false),
            FS_OP_BDEV_PASSTHROUGH_NOTED
        );
        assert_eq!(bdev_verdict(p, b, BDEV_ACCESS_READ, 0, false), 0);
        assert!(!bdev_refuses(FS_OP_BDEV_WRITE_NOTED));
        assert!(!bdev_refuses(FS_OP_BDEV_PASSTHROUGH_NOTED));
        // under the kernel-read option's block-device class: each refused
        assert_eq!(
            bdev_verdict(p, b, BDEV_ACCESS_WRITE, strict, false),
            FS_OP_BDEV_WRITE
        );
        assert_eq!(
            bdev_verdict(p, b, BDEV_ACCESS_PASSTHROUGH, strict, false),
            FS_OP_BDEV_PASSTHROUGH
        );
        assert_eq!(
            bdev_verdict(p, b, BDEV_ACCESS_READ, strict, false),
            FS_OP_BDEV_READ
        );
        assert!(bdev_refuses(FS_OP_BDEV_WRITE));
        assert!(bdev_refuses(FS_OP_BDEV_PASSTHROUGH));
        assert!(bdev_refuses(FS_OP_BDEV_READ));
        // another class of the option is not the block devices'
        assert_eq!(
            bdev_verdict(p, b, BDEV_ACCESS_WRITE, !KERNEL_READ_BLOCK_DEVICE, false),
            FS_OP_BDEV_WRITE_NOTED
        );
        assert_eq!(
            bdev_verdict(p, b, BDEV_ACCESS_READ, !KERNEL_READ_BLOCK_DEVICE, false),
            0
        );
        // lifted for a member of the window
        for a in [BDEV_ACCESS_READ, BDEV_ACCESS_WRITE, BDEV_ACCESS_PASSTHROUGH] {
            assert_eq!(bdev_verdict(p, b, a, strict, true), 0);
            assert_eq!(bdev_verdict(p, b, a, 0, true), 0);
        }
        // another device, or an entry without the bit
        assert_eq!(bdev_verdict(None, b, BDEV_ACCESS_WRITE, strict, false), 0);
        assert_eq!(
            bdev_verdict(Some(0), b, BDEV_ACCESS_WRITE, strict, false),
            0
        );
    }

    #[test]
    fn a_disk_s_passthrough_nodes_are_judged_at_their_commands_and_writes_not_their_reads() {
        let c = bdev_entry_bit(false);
        assert_eq!(c, BDEV_PASSTHROUGH_NODE);
        assert_eq!(bdev_entry_bit(true), BDEV_BACKS_PROTECTED);
        let node = Some(BDEV_PASSTHROUGH_NODE);
        let strict = KERNEL_READ_BLOCK_DEVICE;
        assert_eq!(
            bdev_verdict(node, c, BDEV_ACCESS_PASSTHROUGH, 0, false),
            FS_OP_BDEV_PASSTHROUGH_NOTED
        );
        assert_eq!(
            bdev_verdict(node, c, BDEV_ACCESS_PASSTHROUGH, strict, false),
            FS_OP_BDEV_PASSTHROUGH
        );
        // the sg node's write interface sends commands too
        assert_eq!(
            bdev_verdict(node, c, BDEV_ACCESS_WRITE, strict, false),
            FS_OP_BDEV_WRITE
        );
        assert_eq!(bdev_verdict(node, c, BDEV_ACCESS_READ, strict, false), 0);
        // one number, two devices: each matches its own bit
        assert_eq!(
            bdev_verdict(node, BDEV_BACKS_PROTECTED, BDEV_ACCESS_WRITE, strict, false),
            0
        );
        assert_eq!(
            bdev_verdict(
                Some(BDEV_BACKS_PROTECTED),
                c,
                BDEV_ACCESS_PASSTHROUGH,
                strict,
                false
            ),
            0
        );
        let both = Some(BDEV_BACKS_PROTECTED | BDEV_PASSTHROUGH_NODE);
        assert_eq!(
            bdev_verdict(both, c, BDEV_ACCESS_WRITE, 0, false),
            FS_OP_BDEV_WRITE_NOTED
        );
    }

    #[test]
    fn the_passthrough_ioctls_are_scsi_s_and_nvme_s_commands() {
        // NVME_IOCTL_ADMIN_CMD, SUBMIT_IO, IO_CMD, ADMIN64_CMD, IO64_CMD, IO64_CMD_VEC
        for cmd in [
            0xC048_4E41u32,
            0x4030_4E42,
            0xC048_4E43,
            0xC050_4E47,
            0xC050_4E48,
            0xC050_4E49,
        ] {
            assert!(is_passthrough_ioctl(cmd), "{cmd:#x}");
        }
        assert!(is_passthrough_ioctl(SG_IO));
        assert!(is_passthrough_ioctl(SCSI_IOCTL_SEND_COMMAND));
        // NVME_IOCTL_ID, RESET, RESCAN; BLKGETSIZE64, BLKFLSBUF; FS_IOC_SETFLAGS; SG_GET_VERSION_NUM
        for cmd in [
            0x4E40u32,
            0x4E44,
            0x4E46,
            0x8008_1272,
            0x1261,
            0x4008_6602,
            0x2282,
            0,
        ] {
            assert!(!is_passthrough_ioctl(cmd), "{cmd:#x}");
        }
    }

    #[test]
    fn an_ancestor_rename_is_refused_and_kept_for_the_key_directories() {
        let anc = Some(INODE_EXT_NO_RENAME);
        let kept = Some(INODE_EXT_NO_RENAME | INODE_EXT_DIR_KEPT);
        assert!(ancestor_rename_verdict(anc, false, false));
        assert!(!ancestor_rename_verdict(anc, true, false));
        assert!(!ancestor_rename_verdict(anc, false, true));
        assert!(ancestor_rename_verdict(kept, true, false));
        assert!(!ancestor_rename_verdict(kept, true, true));
        assert!(!ancestor_rename_verdict(None, false, false));
        // a key file is no ancestor: its rename is the protected file's
        assert!(!ancestor_rename_verdict(
            Some(INODE_EXT_WINDOW_KEPT),
            false,
            false
        ));
        // a file's kept bit keeps no directory's rename
        assert!(!ancestor_rename_verdict(
            Some(INODE_EXT_NO_RENAME | INODE_EXT_WINDOW_KEPT),
            true,
            false
        ));
    }

    #[test]
    fn the_key_files_are_kept_by_any_window() {
        assert!(window_lift_kept(Some(INODE_EXT_WINDOW_KEPT)));
        assert!(window_lift_kept(Some(
            INODE_EXT_WINDOW_KEPT | INODE_EXT_NO_RENAME
        )));
        assert!(!window_lift_kept(Some(INODE_EXT_NO_RENAME)));
        // the key files' directory: what is done to its entries is lifted
        assert!(!window_lift_kept(Some(
            INODE_EXT_NO_RENAME | INODE_EXT_DIR_KEPT
        )));
        assert!(!window_lift_kept(None));
    }

    #[test]
    fn the_denial_class() {
        assert_eq!(denial_class(false, false), DENIAL_WINDOW_NONE);
        assert_eq!(denial_class(false, true), DENIAL_WINDOW_NONE);
        assert_eq!(denial_class(true, false), DENIAL_WINDOW_OUTSIDER);
        assert_eq!(denial_class(true, true), DENIAL_WINDOW_KEPT);
    }

    /// Lot 2.3a: a new instance is protected before it registers; the
    /// role's live holder, a process of no binary of ours and one past its
    /// first seconds are not (the fixtures' teardown, a helper left behind).
    #[test]
    fn a_new_instance_is_protected_until_it_registers_capped_and_only_as_its_unit_s_start() {
        let young = Some(NEW_INSTANCE_NS - 1);
        // past the former fixed 10 s, still protected (a slow start)
        assert!(new_instance_protected(
            2,
            Some(100),
            200,
            true,
            Some(30_000_000_000)
        ));
        assert!(new_instance_protected(2, Some(100), 200, true, young));
        assert!(new_instance_protected(1, None, 200, true, Some(0)));
        assert!(
            new_instance_protected(2, Some(100), 200, true, None),
            "its start unread"
        );
        assert!(
            !new_instance_protected(0, Some(100), 200, true, young),
            "not our binary"
        );
        assert!(
            !new_instance_protected(2, Some(200), 200, true, young),
            "the role's holder"
        );
        assert!(
            !new_instance_protected(2, Some(100), 200, true, Some(NEW_INSTANCE_NS)),
            "past the cap"
        );
        assert!(
            !new_instance_protected(2, Some(100), 200, false, young),
            "not systemd's start of the role's unit (a test agent, install.sh's check)"
        );
        assert!(!new_instance_protected(2, Some(100), 200, false, None));
        assert_eq!(NEW_INSTANCE_NS, 60_000_000_000);
    }

    #[test]
    fn the_fatal_signals() {
        for s in [
            1, 2, 3, 6, 9, 10, 11, 12, 13, 14, 15, 16, 19, 20, 21, 22, 24, 27, 29, 30, 31, 32, 34,
            64,
        ] {
            assert!(fatal_or_stop_by_default(s), "{s}");
        }
        for s in [0, 17, 18, 23, 28, 65, -1] {
            assert!(!fatal_or_stop_by_default(s), "{s}");
        }
    }

    #[test]
    fn the_fork_span_guards_a_pending_child_a_new_task_and_a_member_s_child() {
        // a member's child made a member at task_alloc, before its entry
        assert!(in_tree_span(true, Some(0), false));
        // a task that has not run (TASK_NEW), whoever forked it
        assert!(in_tree_span(false, Some(TASK_NEW), false));
        assert!(in_tree_span(false, Some(TASK_NEW | 0x1), false));
        // a member's child the map left outside, or evicted before its exec
        assert!(in_tree_span(false, Some(0), true));
        assert!(in_tree_span(false, None, true));
        // none of them: not in the tree
        assert!(!in_tree_span(false, Some(0), false));
        assert!(!in_tree_span(false, Some(0x1), false));
        assert!(!in_tree_span(false, None, false));
        assert_eq!(TASK_NEW, 0x0800);
    }

    #[test]
    fn a_let_through_record_takes_no_window_class() {
        use crate::wire::{
            FS_OP_FATAL_SIGNAL, FS_OP_MOUNT_NOTED, FS_OP_MOUNT_WINDOW, FS_OP_PTRACE, FS_OP_SIGNAL,
            FS_OP_SYSRQ_WINDOW, FS_OP_UNLINK, FS_OP_WRITE, is_sole_trace,
        };
        for op in [
            FS_OP_FATAL_SIGNAL,
            FS_OP_MOUNT_NOTED,
            FS_OP_MOUNT_WINDOW,
            FS_OP_SYSRQ_WINDOW,
            FS_OP_BDEV_WRITE_NOTED,
            FS_OP_BDEV_PASSTHROUGH_NOTED,
        ] {
            assert!(!window_classes(op), "{op}");
        }
        for op in 1..=crate::wire::FS_OP_LAST {
            if is_sole_trace(op) {
                assert!(!window_classes(op), "{op}");
            }
        }
        for op in [
            FS_OP_SIGNAL,
            FS_OP_PTRACE,
            FS_OP_UNLINK,
            FS_OP_WRITE,
            FS_OP_BDEV_WRITE,
            FS_OP_BDEV_PASSTHROUGH,
            FS_OP_BDEV_READ,
        ] {
            assert!(window_classes(op), "{op}");
        }
    }

    #[test]
    fn our_units_links_are_kept_by_name_in_their_directories() {
        for n in UNIT_LINK_NAMES {
            assert!(n.len() < 32);
            assert!(
                is_unit_link_name(&name_words4(n)),
                "{}",
                String::from_utf8_lossy(n)
            );
        }
        for n in [
            &b"northnarrow-agent.servic"[..],
            b"northnarrow-agent.service~",
            b"northnarrow-agent.socket",
            b"getty@tty1.service",
            b"",
        ] {
            assert!(
                !is_unit_link_name(&name_words4(n)),
                "{}",
                String::from_utf8_lossy(n)
            );
        }
        let d = Some(INODE_EXT_UNIT_LINKS | INODE_EXT_NO_RENAME);
        assert!(unit_link_verdict(d, true, false, false));
        assert!(
            !unit_link_verdict(d, false, false, false),
            "another unit's link"
        );
        assert!(
            !unit_link_verdict(d, true, true, false),
            "lifted by a window"
        );
        assert!(
            !unit_link_verdict(d, true, false, true),
            "the agent's family"
        );
        assert!(!unit_link_verdict(
            Some(INODE_EXT_NO_RENAME),
            true,
            false,
            false
        ));
        assert!(!unit_link_verdict(None, true, false, false));
    }

    #[test]
    fn the_shell_apt_interpreter_and_git_variables_evict() {
        for v in [
            &b"BASH_FUNC_ls%%=() { id; }"[..],
            b"SHELLOPTS=xtrace",
            b"BASHOPTS=extdebug",
            b"APT_CONFIG=/tmp/apt.conf",
            b"NODE_OPTIONS=--require /tmp/x.js",
            b"RUBYOPT=-r/tmp/x",
            b"JAVA_TOOL_OPTIONS=-javaagent:/tmp/a.jar",
            b"_JAVA_OPTIONS=-Dx=y",
            b"LUA_INIT=@/tmp/x.lua",
            b"LUA_INIT_5_4=os.execute('id')",
            b"PYTHONHOME=/tmp/py",
            b"PERL5DB=exec id",
            b"GIT_SSH_COMMAND=id",
            b"GIT_CONFIG_COUNT=1",
            b"GIT_CONFIG_PARAMETERS='core.fsmonitor=id'",
            b"GIT_EXEC_PATH=/tmp",
        ] {
            assert!(env_var_dangerous(v), "{}", String::from_utf8_lossy(v));
        }
        for v in [
            &b"PATH=/usr/bin"[..],
            b"HOME=/root",
            b"LANG=C.UTF-8",
            b"GIT_AUTHOR_NAME=x",
            b"SHELL=/bin/bash",
            b"DEBIAN_FRONTEND=noninteractive",
            b"BASH=/bin/bash",
        ] {
            assert!(!env_var_dangerous(v), "{}", String::from_utf8_lossy(v));
        }
    }
}
