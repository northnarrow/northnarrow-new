//! Wave 4, lab PR 226 (EXPERIMENTAL) — synchronous exec policies (CM-01)
//! and exec-environment / executable-mapping checks (CM-25): the kernel ↔
//! agent contract (design `docs/design/EXEC_POLICY.md`).
//!
//! The LSM exec sensor (`agent-ebpf/src/exec_lsm.rs`) classifies the file
//! of each binfmt pass (the classes of lab PR 223, [`super::execq::class`])
//! and, when the file is in a class or the new environment carries one of
//! the loader variables, works out the caller's lineage tier ([`tier`]). The
//! frozen policy ([`conf_slot`]) gives, per tier, the classes to deny, to
//! record as "would deny", and to hand to the exec quarantine; a deny is
//! `-EACCES` from `bprm_check_security`, before the exec's point of no
//! return. The environment is read at the exec's first pass from the exec's
//! own syscall registers ([`EnvStashRaw`], a bounded prefix, in the task's
//! own [`TaskKey`] entry; lot 322) and judged there. The `mmap_file`
//! LSM hook applies the same classes to executable mappings of files.
//!
//! Every struct is `#[repr(C)]` with explicit padding; strict append-only.

use super::exe::ExeIdentityRaw;
pub use super::exe::TaskKey;
use super::TASK_COMM_LEN;

/// Lineage tiers of the exec'ing task (`ExecPolRaw::tier`, low byte).
pub mod tier {
    /// None of the others: no systemd slice to place it, a slice the
    /// policy does not name (containers on the cgroupfs driver,
    /// `machine.slice`), a user slice without a login uid. The strictest
    /// column of the default tables.
    pub const UNKNOWN: u32 = 0;
    /// An administrator's interactive session: in `user.slice`, uid 0, a
    /// controlling terminal, a login uid, and either a root login
    /// (login uid 0) or an elevation binary (sudo, su, doas, pkexec, run0)
    /// in the lineage.
    pub const ADMIN: u32 = 1;
    /// A login session that is not an interactive admin session (`user.slice`
    /// with a login uid): a user's shell or desktop, `ssh host cmd`.
    pub const SESSION: u32 = 2;
    /// A system service (`system.slice`): a unit, a cron job, a
    /// `systemd-run` command, a container under the systemd cgroup driver.
    pub const SERVICE: u32 = 3;
    /// Tiers (table columns).
    pub const COUNT: u32 = 4;
    /// The tier value of `ExecPolRaw::tier`.
    pub const MASK: u32 = 0xff;
}

/// The signals the tier was computed from (`ExecPolRaw::tier`, above the
/// low byte), for the record.
pub mod tier_sig {
    /// `task->signal->tty` is set.
    pub const TTY: u32 = 1 << 8;
    /// A login uid is set.
    pub const LOGIN: u32 = 1 << 9;
    /// An elevation binary's image in the lineage (8 hops at most).
    pub const ELEVATED: u32 = 1 << 10;
    /// Real uid 0.
    pub const ROOT: u32 = 1 << 11;
    /// In `system.slice`.
    pub const SYSTEM_SLICE: u32 = 1 << 12;
    /// In `user.slice`.
    pub const USER_SLICE: u32 = 1 << 13;
    /// The agent published no slice ids (no cgroup v2, no systemd): every
    /// caller is `unknown`.
    pub const NO_SLICES: u32 = 1 << 14;
    /// The caller's image is one the policy exempts for the classes of
    /// this exec (a container runtime's self-protection copy, init).
    pub const EXEMPT_IMAGE: u32 = 1 << 15;
    /// The exec re-runs the caller's own image (`/proc/self/exe` of a
    /// program whose file was replaced since it started).
    pub const SELF_REEXEC: u32 = 1 << 16;
    /// Lot 273d (the last review of #497, NC2): in the units' own
    /// `northnarrow.slice` (a service slice, as `system.slice`).
    pub const OUR_SLICE: u32 = 1 << 17;
}

/// `EXECPOL_CONF` slots (an `Array<u64>`, written once by the agent before
/// the policy is enforced, then frozen).
pub mod conf_slot {
    /// [`super::mode`].
    pub const MODE: u32 = 0;
    /// `DENY + tier`: the classes denied for that tier.
    pub const DENY: u32 = 1;
    /// `QUARANTINE + tier`: the classes handed to the exec quarantine.
    pub const QUARANTINE: u32 = 5;
    /// `AUDIT + tier`: the classes recorded as "would deny" (allowed).
    pub const AUDIT: u32 = 9;
    /// Classes in audit mode: their deny cells are recorded, not applied.
    pub const CLASS_AUDIT: u32 = 13;
    /// Tiers (bit per tier) where a loader variable into a staging path is
    /// denied whatever the caller's uid.
    pub const ENV_DENY: u32 = 14;
    /// Tiers where it is denied when the caller is root (no `AT_SECURE`:
    /// the loader honours it with root's credentials).
    pub const ENV_DENY_ROOT: u32 = 15;
    /// Tiers whose loader-variable findings are reported.
    pub const ENV_RECORD: u32 = 16;
    /// `MAP_DENY + tier`: classes whose executable mappings are denied.
    pub const MAP_DENY: u32 = 17;
    /// `MAP_RECORD + tier`: classes whose executable mappings are reported.
    pub const MAP_RECORD: u32 = 21;
    /// [`super::flags`].
    pub const FLAGS: u32 = 25;
    /// Slots in the map.
    pub const SLOTS: u32 = 32;
}

/// `EXECPOL_CONF[MODE]`.
pub mod mode {
    /// Nothing is classified for the policy, nothing denied (the default).
    pub const OFF: u64 = 0;
    /// Every deny is recorded as "would deny" and the exec runs; quarantine
    /// cells still hand the exec to the exec quarantine. A detect-only
    /// agent audits.
    pub const AUDIT: u64 = 1;
    /// Deny cells return `-EACCES`.
    pub const ENFORCE: u64 = 2;
}

/// `EXECPOL_CONF[FLAGS]`.
pub mod flags {
    /// The exec's first pass reads the new environment (lot 322: from the
    /// exec's own registers; it was two `sys_enter_execve{,at}` programs).
    pub const ENV_SCAN: u64 = 1 << 0;
    /// The `mmap_file` program judges executable mappings.
    pub const MAP: u64 = 1 << 1;
    /// The exec quarantine holds only the execs a quarantine cell names
    /// (the policy decides; without it the guard holds every candidate of
    /// its classes, as in lab PR 223).
    pub const QUARANTINE_BY_POLICY: u64 = 1 << 2;
}

/// `EXECPOL_SLICES` slots (`Array<u64>`, refreshed by the agent): the
/// cgroup v2 ids of the top-level systemd slices.
pub mod slice_slot {
    pub const SYSTEM: u32 = 0;
    pub const USER: u32 = 1;
    /// Lot 273d (the short re-check of #497, NB5): the units' own
    /// `northnarrow.slice` — a service tier, as `system.slice` was for them.
    pub const OURS: u32 = 2;
    pub const SLOTS: u32 = 3;
}

/// `EXECPOL_IMAGES` value bits: what an executable image (by `(dev, ino)`)
/// is to the policy. The low 16 bits are the classes ([`super::execq::class`])
/// a caller running that image is exempt from.
pub mod image_role {
    /// Exempt classes (the low half).
    pub const EXEMPT_MASK: u32 = 0xffff;
    /// An elevation binary (sudo, su, doas, pkexec, run0): its presence in
    /// the lineage is one of the admin tier's signals.
    pub const ELEVATION: u32 = 1 << 16;
}

/// Decision bits (`ExecPolRaw::action`, `env_action`).
pub mod action {
    /// Refused (`-EACCES`).
    pub const DENY: u32 = 1 << 0;
    /// A deny not applied: audit mode (global, or the class's), an audit
    /// cell — recorded as "would deny".
    pub const WOULD_DENY: u32 = 1 << 1;
    /// Handed to the exec quarantine.
    pub const QUARANTINE: u32 = 1 << 2;
    /// A quarantine cell while the exec quarantine is off: the exec runs.
    pub const QUARANTINE_INACTIVE: u32 = 1 << 3;
    /// Recorded only (environment findings, mappings).
    pub const RECORD: u32 = 1 << 4;
    /// An exemption removed classes from a deny (`tier_sig` says which).
    pub const EXEMPTED: u32 = 1 << 5;
}

/// `ExecPolRaw::kind`.
pub mod kind {
    /// An exec pass: classes and/or the environment.
    pub const EXEC: u32 = 1;
    /// An executable mapping (`mmap_file`).
    pub const MAP: u32 = 2;
}

/// Environment findings (`EnvStashRaw::flags`, `ExecPolRaw::env_flags`).
pub mod env_flags {
    pub const LD_PRELOAD: u32 = 1 << 0;
    pub const LD_AUDIT: u32 = 1 << 1;
    pub const LD_LIBRARY_PATH: u32 = 1 << 2;
    pub const GLIBC_TUNABLES: u32 = 1 << 3;
    pub const HISTFILE: u32 = 1 << 4;
    /// `HISTSIZE=0`.
    pub const HISTSIZE_ZERO: u32 = 1 << 5;
    /// `HISTFILESIZE=0`.
    pub const HISTFILESIZE_ZERO: u32 = 1 << 6;
    /// `HISTCONTROL=ignore…` exported.
    pub const HISTCONTROL_IGNORE: u32 = 1 << 7;
    /// More than [`super::ENV_SCAN_MAX`] variables: the rest was not read.
    pub const TRUNCATED: u32 = 1 << 8;
    /// An `LD_PRELOAD` entry under a staging prefix ([`super::STAGING_PREFIXES`]).
    pub const PRELOAD_STAGING: u32 = 1 << 9;
    /// An `LD_AUDIT` entry under a staging prefix.
    pub const AUDIT_STAGING: u32 = 1 << 10;
    /// An `LD_LIBRARY_PATH` entry under a staging prefix.
    pub const LIBPATH_STAGING: u32 = 1 << 11;
    /// `HISTFILE` empty or `/dev/null`.
    pub const HISTFILE_NULL: u32 = 1 << 12;
    /// The environment array could not be read.
    pub const UNREADABLE: u32 = 1 << 13;
    /// A captured value filled its buffer: entries past it were not seen.
    pub const VALUE_CUT: u32 = 1 << 14;
    /// Loader variables that can load code.
    pub const LOADER: u32 = LD_PRELOAD | LD_AUDIT;
    /// Findings a deny can rest on.
    pub const DENYABLE: u32 = PRELOAD_STAGING | AUDIT_STAGING;
    /// History tricks.
    pub const HISTORY: u32 = HISTFILE_NULL | HISTSIZE_ZERO | HISTFILESIZE_ZERO | HISTCONTROL_IGNORE;
}

/// Environment variables read at most per exec (bounded loop).
pub const ENV_SCAN_MAX: usize = 64;
/// Bytes of each variable compared (the name and the start of the value).
pub const ENV_PREFIX_LEN: usize = 24;
/// Captured value lengths.
pub const ENV_PRELOAD_LEN: usize = 128;
pub const ENV_AUDIT_LEN: usize = 64;
pub const ENV_TUNABLES_LEN: usize = 128;
pub const ENV_LIBPATH_LEN: usize = 64;
pub const ENV_HIST_LEN: usize = 16;

/// Staging prefixes a loader variable entry is compared against in the
/// kernel (string prefixes of the value, not resolved paths: `//tmp/x`, a
/// symlink or `..` pass this check and meet the `mmap_file` one, which
/// classifies the file the loader actually maps).
pub const STAGING_PREFIXES: [&str; 5] = ["/tmp/", "/var/tmp/", "/dev/shm/", "/proc/", "/dev/fd/"];

/// The new environment's loader findings, read and judged at the exec's
/// first pass (`EXECPOL_ENV`, the exec'ing task's own [`TaskKey`]
/// entry; lot 322). 416 bytes, no implicit padding.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct EnvStashRaw {
    /// [`env_flags`].
    pub flags: u32,
    /// Variables read.
    pub count: u32,
    /// `GLIBC_TUNABLES` value length read (`ENV_TUNABLES_LEN - 1` when cut).
    pub tunables_len: u32,
    pub _pad: u32,
    pub preload: [u8; ENV_PRELOAD_LEN],
    pub audit: [u8; ENV_AUDIT_LEN],
    pub tunables: [u8; ENV_TUNABLES_LEN],
    pub libpath: [u8; ENV_LIBPATH_LEN],
    pub hist: [u8; ENV_HIST_LEN],
}

impl EnvStashRaw {
    pub const fn zeroed() -> Self {
        Self {
            flags: 0,
            count: 0,
            tunables_len: 0,
            _pad: 0,
            preload: [0; ENV_PRELOAD_LEN],
            audit: [0; ENV_AUDIT_LEN],
            tunables: [0; ENV_TUNABLES_LEN],
            libpath: [0; ENV_LIBPATH_LEN],
            hist: [0; ENV_HIST_LEN],
        }
    }
}

/// `EXECMAP_SEEN` value: the classes of a mapped file, under the content
/// stamp they were computed with (a rename or a write moves ctime), and
/// when it was last reported.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct MapSeen {
    pub ctime_sec: i64,
    pub ctime_nsec: u32,
    pub classes: u32,
    /// Last report (CLOCK_MONOTONIC ns), 0 never.
    pub reported_ns: u64,
}

/// A mapping of the same file is reported at most this often.
pub const MAP_REPORT_EVERY_NS: u64 = 60_000_000_000;

/// `EXECPOL_COUNTERS` slots (per-CPU `u64`, summed by the agent).
pub mod counter {
    /// Execs refused.
    pub const DENIED: u32 = 0;
    /// Execs a deny cell named, allowed (audit).
    pub const WOULD_DENY: u32 = 1;
    /// Execs handed to the exec quarantine.
    pub const QUARANTINE: u32 = 2;
    /// Quarantine cells while the exec quarantine is off.
    pub const QUARANTINE_INACTIVE: u32 = 3;
    /// Execs refused on their environment.
    pub const ENV_DENIED: u32 = 4;
    /// Environment findings reported.
    pub const ENV_RECORDED: u32 = 5;
    /// Executable mappings refused.
    pub const MAP_DENIED: u32 = 6;
    /// Executable mappings reported (or "would deny").
    pub const MAP_RECORDED: u32 = 7;
    /// Classes removed from a deny by an exemption.
    pub const EXEMPTED: u32 = 8;
    /// Reports the ring could not hold (the decision still applied).
    pub const RING_FULL: u32 = 9;
    /// Environments with more than `ENV_SCAN_MAX` variables.
    pub const ENV_TRUNCATED: u32 = 10;
    /// Lot 322: environments not read whole (`env_flags::UNREADABLE`): the
    /// array or a string unreadable at the exec's first pass (the caller's
    /// memory changed after the kernel's copy), an exec entered by a call
    /// [`exec_envp_reg`] does not know, or the task's stash not made. Each
    /// one is also recorded (`NN-L-EXECENV-002`, High); none is refused.
    /// The agent reports the total (`nn-admin status`).
    pub const ENV_UNREAD: u32 = 11;
    /// Lot 322 (the review of #546, F4/F5): a run whose per-task buffer could
    /// not be made (the map full: that many runs in flight) — the exec
    /// sensor's walk (refused in enforce mode), the mapping check's walk
    /// (classed `tmp`, `var_tmp`, `home`), the quarantine's candidate. The
    /// agent reports the total.
    pub const LOST: u32 = 12;
    /// Slots in the map.
    pub const SLOTS: u32 = 13;
}

/// One policy report (a deny, a "would deny", an environment finding, an
/// executable mapping), as the kernel writes it on `EXECPOL_EVENTS`.
/// 1 056 bytes, no implicit padding.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct ExecPolRaw {
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    /// `u32::MAX` when unset or unknown.
    pub loginuid: u32,
    /// CLOCK_MONOTONIC ns.
    pub timestamp_ns: u64,
    /// The caller's `task_struct.start_time`.
    pub start_ns: u64,
    /// The caller's cgroup v2 id.
    pub cgroup_id: u64,
    /// [`kind`].
    pub kind: u32,
    /// [`tier`] in the low byte, [`tier_sig`] above.
    pub tier: u32,
    /// The file's classes ([`super::execq::class`]).
    pub classes: u32,
    /// [`action`] bits for the classes.
    pub action: u32,
    /// [`env_flags`].
    pub env_flags: u32,
    /// [`action`] bits for the environment.
    pub env_action: u32,
    /// Variables read.
    pub env_count: u32,
    /// The file's `i_mode` (set-id bits: `AT_SECURE` will apply).
    pub file_mode: u32,
    /// The file's owner.
    pub file_uid: u32,
    pub tunables_len: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub preload: [u8; ENV_PRELOAD_LEN],
    pub audit: [u8; ENV_AUDIT_LEN],
    pub tunables: [u8; ENV_TUNABLES_LEN],
    pub libpath: [u8; ENV_LIBPATH_LEN],
    pub hist: [u8; ENV_HIST_LEN],
    /// The file (an exec pass, or the mapped file).
    pub exe: ExeIdentityRaw,
}

impl ExecPolRaw {
    pub const fn zeroed() -> Self {
        Self {
            pid: 0,
            tid: 0,
            ppid: 0,
            uid: 0,
            gid: 0,
            loginuid: 0,
            timestamp_ns: 0,
            start_ns: 0,
            cgroup_id: 0,
            kind: 0,
            tier: 0,
            classes: 0,
            action: 0,
            env_flags: 0,
            env_action: 0,
            env_count: 0,
            file_mode: 0,
            file_uid: 0,
            tunables_len: 0,
            comm: [0; TASK_COMM_LEN],
            preload: [0; ENV_PRELOAD_LEN],
            audit: [0; ENV_AUDIT_LEN],
            tunables: [0; ENV_TUNABLES_LEN],
            libpath: [0; ENV_LIBPATH_LEN],
            hist: [0; ENV_HIST_LEN],
            exe: ExeIdentityRaw::zeroed(),
        }
    }

    /// The tier (low byte of [`Self::tier`]).
    pub const fn tier_value(&self) -> u32 {
        self.tier & tier::MASK
    }

    /// The target is set-user-ID or set-group-ID (its mode only: whether
    /// the exec changes the credentials is [`Self::at_secure`]).
    pub const fn target_setid(&self) -> bool {
        self.file_mode & 0o6000 != 0
    }

    /// The kernel sets `AT_SECURE` for this exec — the loader then ignores
    /// `LD_PRELOAD` entries with a slash, `LD_LIBRARY_PATH` and unsafe
    /// `LD_AUDIT` values — only when the exec changes the credentials:
    /// the effective uid becomes another than the real one (a set-user-ID
    /// file owned by another user than the caller's real uid, [`Self::uid`])
    /// or the effective gid another than the real one (a set-group-ID file:
    /// the record does not carry the file's group, so a set-group-ID target
    /// counts as changing it — as it does for every caller outside that
    /// group).
    ///
    /// Lot 315 (external bug hunt 1.4, BUG-101, the record's half): the
    /// set-id bits alone said `AT_SECURE` for root running a
    /// set-user-ID-root file (`su`, `passwd`, `mount`), which changes no
    /// credential: the loader honours the preload, as root, and the record
    /// said it was ignored. A `file_uid` read as 0 (the kernel's `i_uid`
    /// offset not resolved) keeps it so for a caller other than root and
    /// says "not secure" for root — the side that does not claim a
    /// neutralised preload. The kernel's half (the deny skipped for every
    /// set-id target) is lot 318's.
    pub const fn at_secure(&self) -> bool {
        (self.file_mode & 0o4000 != 0 && self.file_uid != self.uid) || self.file_mode & 0o2000 != 0
    }
}

/// Tier names, for records, logs and the policy file.
#[cfg(feature = "std")]
pub fn tier_name(t: u32) -> &'static str {
    match t & tier::MASK {
        tier::ADMIN => "admin",
        tier::SESSION => "session",
        tier::SERVICE => "service",
        _ => "unknown",
    }
}

/// The signals a tier was computed from, by name.
#[cfg(feature = "std")]
pub fn tier_signals(v: u32) -> alloc::vec::Vec<&'static str> {
    let mut out = alloc::vec::Vec::new();
    for (bit, name) in [
        (tier_sig::TTY, "tty"),
        (tier_sig::LOGIN, "login_uid"),
        (tier_sig::ELEVATED, "elevation_binary"),
        (tier_sig::ROOT, "uid_0"),
        (tier_sig::SYSTEM_SLICE, "system.slice"),
        (tier_sig::USER_SLICE, "user.slice"),
        (tier_sig::NO_SLICES, "no_slices"),
        (tier_sig::EXEMPT_IMAGE, "exempt_image"),
        (tier_sig::SELF_REEXEC, "self_reexec"),
        (tier_sig::OUR_SLICE, "northnarrow.slice"),
    ] {
        if v & bit != 0 {
            out.push(name);
        }
    }
    out
}

/// Environment finding names.
#[cfg(feature = "std")]
pub fn env_names(bits: u32) -> alloc::vec::Vec<&'static str> {
    let mut out = alloc::vec::Vec::new();
    for (bit, name) in [
        (env_flags::LD_PRELOAD, "LD_PRELOAD"),
        (env_flags::LD_AUDIT, "LD_AUDIT"),
        (env_flags::LD_LIBRARY_PATH, "LD_LIBRARY_PATH"),
        (env_flags::GLIBC_TUNABLES, "GLIBC_TUNABLES"),
        (env_flags::HISTFILE, "HISTFILE"),
        (env_flags::HISTSIZE_ZERO, "HISTSIZE=0"),
        (env_flags::HISTFILESIZE_ZERO, "HISTFILESIZE=0"),
        (env_flags::HISTCONTROL_IGNORE, "HISTCONTROL=ignore*"),
        (env_flags::TRUNCATED, "truncated"),
        (env_flags::PRELOAD_STAGING, "preload_staging"),
        (env_flags::AUDIT_STAGING, "audit_staging"),
        (env_flags::LIBPATH_STAGING, "library_path_staging"),
        (env_flags::HISTFILE_NULL, "histfile_null"),
        (env_flags::UNREADABLE, "unreadable"),
        (env_flags::VALUE_CUT, "value_cut"),
    ] {
        if bits & bit != 0 {
            out.push(name);
        }
    }
    out
}

/// Whether one loader-variable entry starts with a staging prefix — the
/// same comparison the kernel makes, for tests and for the userland
/// re-check of a captured value.
pub fn entry_is_staging(entry: &[u8]) -> bool {
    STAGING_PREFIXES
        .iter()
        .any(|p| entry.len() >= p.len() && &entry[..p.len()] == p.as_bytes())
}

/// x86-64 `execve(2)` and `execveat(2)`, `orig_ax` at `bprm_check_security`.
pub const NR_EXECVE: u64 = 59;
pub const NR_EXECVEAT: u64 = 322;
/// The same through the 32-bit entry (`int $0x80`, `sysenter`): any
/// process can make it, a 64-bit one included (the review of #546, F1).
pub const IA32_NR_EXECVE: u64 = 11;
pub const IA32_NR_EXECVEAT: u64 = 358;
/// The same through the x32 ABI (`__X32_SYSCALL_BIT`, where the kernel has
/// `CONFIG_X86_X32_ABI`).
pub const X32_SYSCALL_BIT: u64 = 0x4000_0000;
pub const X32_NR_EXECVE: u64 = X32_SYSCALL_BIT | 520;
pub const X32_NR_EXECVEAT: u64 = X32_SYSCALL_BIT | 545;

/// The register of the exec's `pt_regs` that holds `envp`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EnvpReg {
    /// Native and x32 `execve(filename, argv, envp)`, ia32 `execve`
    /// (`edx`): the third argument.
    Dx,
    /// Native and x32 `execveat(dirfd, filename, argv, envp, flags)`: the
    /// fourth.
    R10,
    /// ia32 `execveat` (`ebx, ecx, edx, esi, edi`): the fourth, `esi`.
    Si,
}

/// Lot 322: where the exec's new environment is, from the syscall number
/// the exec entered with, and whether it is a compat one — `envp` then a
/// 32-bit address (the register's low half: the kernel reads no more) of
/// an array of 32-bit pointers. `bprm_check_security` is reached from
/// these six calls (and `kernel_execve`, whose task has no user registers:
/// the caller does not ask): 11 and 358 are no native exec (`munmap`, none),
/// 59 and 322 no 32-bit one. `None`: not read (counted and recorded as
/// [`counter::ENV_UNREAD`]).
#[inline(always)]
pub const fn exec_envp_reg(orig_ax: u64) -> Option<(EnvpReg, bool)> {
    match orig_ax {
        NR_EXECVE => Some((EnvpReg::Dx, false)),
        NR_EXECVEAT => Some((EnvpReg::R10, false)),
        IA32_NR_EXECVE => Some((EnvpReg::Dx, true)),
        IA32_NR_EXECVEAT => Some((EnvpReg::Si, true)),
        X32_NR_EXECVE => Some((EnvpReg::Dx, true)),
        X32_NR_EXECVEAT => Some((EnvpReg::R10, true)),
        _ => None,
    }
}

/// Lot 322: `envp` as the kernel reads it — a compat call's register
/// truncated to its low 32 bits (a 64-bit caller of `int $0x80` may leave
/// the high half set: the kernel ignores it, so must the scan).
#[inline(always)]
pub const fn envp_value(reg: u64, compat: bool) -> u64 {
    if compat {
        reg & 0xffff_ffff
    } else {
        reg
    }
}

/// Lot 322: the size of one entry of the `envp` array (8, or 4 for a
/// compat call): `8 - 4 * compat`, an arithmetic form the verifier bounds
/// to [4, 8] without splitting the scan's loop in two.
#[inline(always)]
pub const fn envp_stride(compat: u64) -> u64 {
    8 - 4 * (compat & 1)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn layouts_are_fixed() {
        assert_eq!(core::mem::size_of::<EnvStashRaw>(), 416);
        assert_eq!(core::mem::size_of::<MapSeen>(), 24);
        assert_eq!(core::mem::size_of::<ExecPolRaw>(), 1056);
        assert_eq!(core::mem::offset_of!(ExecPolRaw, exe), 504);
        assert_eq!(core::mem::align_of::<ExecPolRaw>(), 8);
        assert_eq!(core::mem::size_of::<ExecPolRaw>() % 8, 0);
    }

    #[test]
    fn conf_slots_do_not_overlap() {
        let mut used = [false; conf_slot::SLOTS as usize];
        let mut take = |s: u32| {
            assert!(!used[s as usize], "slot {s} twice");
            used[s as usize] = true;
        };
        take(conf_slot::MODE);
        for t in 0..tier::COUNT {
            take(conf_slot::DENY + t);
            take(conf_slot::QUARANTINE + t);
            take(conf_slot::AUDIT + t);
            take(conf_slot::MAP_DENY + t);
            take(conf_slot::MAP_RECORD + t);
        }
        take(conf_slot::CLASS_AUDIT);
        take(conf_slot::ENV_DENY);
        take(conf_slot::ENV_DENY_ROOT);
        take(conf_slot::ENV_RECORD);
        take(conf_slot::FLAGS);
    }

    #[test]
    fn names() {
        assert_eq!(tier_name(tier::SERVICE | tier_sig::TTY), "service");
        assert_eq!(tier_name(tier::ADMIN), "admin");
        assert_eq!(tier_name(7), "unknown");
        assert_eq!(
            tier_signals(tier_sig::TTY | tier_sig::ELEVATED),
            ["tty", "elevation_binary"]
        );
        assert_eq!(
            env_names(env_flags::LD_PRELOAD | env_flags::PRELOAD_STAGING),
            ["LD_PRELOAD", "preload_staging"]
        );
    }

    #[test]
    fn staging_entries() {
        for yes in [
            "/tmp/x.so",
            "/var/tmp/a/b.so",
            "/dev/shm/l",
            "/proc/self/fd/3",
            "/dev/fd/4",
        ] {
            assert!(entry_is_staging(yes.as_bytes()), "{yes}");
        }
        for no in [
            "/usr/lib/libjemalloc.so.2",
            "libfoo.so",
            "/tmpx/a",
            "/var/tmpx",
            "",
        ] {
            assert!(!entry_is_staging(no.as_bytes()), "{no}");
        }
    }

    /// Lot 322: `envp` is `execve`'s third argument and `execveat`'s
    /// fourth, native or x32; ia32's `execveat` passes it in `esi`. The
    /// review of #546 (F1): the 32-bit and x32 entries are read too, as
    /// 32-bit pointers; an unknown call is not.
    #[test]
    fn the_new_environment_is_found_in_the_exec_s_own_registers() {
        assert_eq!(exec_envp_reg(59), Some((EnvpReg::Dx, false)));
        assert_eq!(exec_envp_reg(322), Some((EnvpReg::R10, false)));
        assert_eq!(exec_envp_reg(11), Some((EnvpReg::Dx, true)));
        assert_eq!(exec_envp_reg(358), Some((EnvpReg::Si, true)));
        assert_eq!(exec_envp_reg(0x4000_0000 | 520), Some((EnvpReg::Dx, true)));
        assert_eq!(exec_envp_reg(0x4000_0000 | 545), Some((EnvpReg::R10, true)));
        // kernel_execve's zeroed registers, a negative (no call), x32's
        // numbers without the bit (no native call), a native call that
        // never execs, a native number with the x32 bit
        for other in [0, u64::MAX, 520, 545, 9, 0x4000_0000 | 59] {
            assert_eq!(exec_envp_reg(other), None, "{other:#x}");
        }
        // the kernel reads a compat envp's low half only, a native one whole
        assert_eq!(envp_value(0xdead_beef_0040_1000, true), 0x0040_1000);
        assert_eq!(envp_value(0x7ffd_0040_1000, false), 0x7ffd_0040_1000);
        assert_eq!(envp_stride(0), 8);
        assert_eq!(envp_stride(1), 4);
        assert_eq!(envp_stride(3), 4);
    }

    #[test]
    fn setid_targets() {
        let mut r = ExecPolRaw::zeroed();
        r.file_mode = 0o100755;
        assert!(!r.target_setid());
        r.file_mode = 0o104755;
        assert!(r.target_setid());
        r.file_mode = 0o102755;
        assert!(r.target_setid());
        r.tier = tier::SESSION | tier_sig::TTY;
        assert_eq!(r.tier_value(), tier::SESSION);
    }

    /// Lot 315 (BUG-101): `AT_SECURE` when the exec changes the
    /// credentials, not for every set-id file.
    #[test]
    fn at_secure_when_the_credentials_change() {
        let mut r = ExecPolRaw::zeroed();
        r.file_mode = 0o104755;
        r.file_uid = 0;
        r.uid = 0;
        assert!(r.target_setid());
        assert!(
            !r.at_secure(),
            "root running a set-uid-root file: no change"
        );
        r.uid = 1000;
        assert!(r.at_secure(), "a user running a set-uid-root file");
        r.file_uid = 1000;
        assert!(!r.at_secure(), "a user running its own set-uid file");
        r.uid = 0;
        assert!(r.at_secure(), "root running a set-uid file of another user");
        r.file_mode = 0o102755;
        r.file_uid = 0;
        assert!(
            r.at_secure(),
            "set-gid: the file's group is not in the record"
        );
        r.file_mode = 0o106755;
        assert!(r.at_secure());
        r.file_mode = 0o100755;
        r.uid = 1000;
        assert!(!r.at_secure(), "no set-id bit");
        r.tier = tier::SESSION | tier_sig::TTY;
        assert_eq!(r.tier_value(), tier::SESSION);
    }
}
