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
    /// Lot 325 (R5): judged without the walk — the per-task buffers were
    /// full — on what needs none (the tier, the file's set-id bits, memfd,
    /// deleted, tmpfs, a world-writable directory, the environment).
    pub const UNWALKED: u32 = 1 << 6;
    /// Lot 325 (TOCTOU): refused after the exec's point of no return — the
    /// new image killed (`SIGKILL`) before its first instruction.
    pub const KILLED: u32 = 1 << 7;
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
    /// The scan could not finish: more than [`super::ENV_SCAN_CAP`]
    /// variables — above any environment the kernel accepts
    /// ([`super::KERNEL_ENVC_MAX`]), so the array grew after the kernel's
    /// count. Lot 325 (R2): counted, recorded High, and refused where the
    /// tier's rule refuses a staging preload or at a set-id target. It was
    /// the 65th variable, neither recorded nor refused.
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
    /// Lot 325 (TOCTOU, the review of #546 F2): the kernel's own copy of the
    /// environment — the new image's, read once the exec is past its point
    /// of no return — holds a staging loader entry the first pass did not
    /// see in the caller's memory: the environment changed between the
    /// kernel's copy and the first pass's read (or that read failed).
    pub const CHANGED: u32 = 1 << 15;
    /// Lot 325 (the mini-hunt of R2): an `LD_PRELOAD` or `LD_AUDIT` value
    /// longer than its capture (128 / 64 bytes): its entries past the cut
    /// were not judged — a staging entry after a long clean one passed.
    /// Judged as an environment the scan could not finish
    /// ([`Self::TRUNCATED`]): refused at a protected or set-id target,
    /// recorded, counted with it.
    pub const LOADER_CUT: u32 = 1 << 16;
    /// Lot 325: what the scan could not judge to its end.
    pub const UNFINISHED: u32 = TRUNCATED | LOADER_CUT;
    /// The review of #547 (F1): an `LD_PRELOAD` or `LD_AUDIT` entry that is a
    /// path relative to the caller's directory (it holds a `/` and does not
    /// start with one: `./x.so`, `lib/x.so`), or a bare name searched in a
    /// staging or relative `LD_LIBRARY_PATH`. Where it resolves is not in
    /// the string: refused at a protected or set-id target, recorded.
    pub const PRELOAD_RELATIVE: u32 = 1 << 17;
    /// The re-check of #547 (G1–G4): a loader variable's value (`LD_PRELOAD`,
    /// `LD_AUDIT`, `LD_LIBRARY_PATH`) holding a control byte (glibc keeps a
    /// tab inside an `LD_PRELOAD` entry; musl splits its library path on a
    /// newline), an empty `LD_LIBRARY_PATH` element (the caller's directory)
    /// or a `$` (glibc expands `$LIB`, `$ORIGIN`, `$PLATFORM`): what the loader
    /// does with it is not in the string as the check reads it. Refused at a
    /// protected or set-id target, recorded elsewhere. Legitimate set-id
    /// execs carry none of them.
    pub const LOADER_IRREGULAR: u32 = 1 << 18;
    /// What the first pass refuses at a protected or set-id target: an
    /// array past the cap (or more judged names than the scan reads), a
    /// relative loader path, an irregular loader value. A loader value longer than the scan reads
    /// (`LOADER_CUT`) is not refused there — the review of #547 (F7): a
    /// clean long value is legitimate — and is judged in the kernel's copy
    /// at the commit.
    pub const FIRST_PASS_FAIL_CLOSED: u32 = TRUNCATED | PRELOAD_RELATIVE | LOADER_IRREGULAR;
    /// What the post-commit check cannot clear in the kernel's copy, which
    /// kills a protected or set-id target (the review of #547, F2).
    pub const UNJUDGED: u32 = UNFINISHED | UNREADABLE | PRELOAD_RELATIVE | LOADER_IRREGULAR;
    /// Loader variables that can load code.
    pub const LOADER: u32 = LD_PRELOAD | LD_AUDIT;
    /// Findings a deny can rest on.
    pub const DENYABLE: u32 = PRELOAD_STAGING | AUDIT_STAGING;
    /// History tricks.
    pub const HISTORY: u32 = HISTFILE_NULL | HISTSIZE_ZERO | HISTFILESIZE_ZERO | HISTCONTROL_IGNORE;
}

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
    /// Environments the scan could not finish (`env_flags::TRUNCATED`:
    /// more than `ENV_SCAN_CAP` variables). Lot 325: reported by the agent
    /// (`nn-admin status`).
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
    /// Lot 325 (TOCTOU): execs whose new image's environment (the kernel's
    /// copy) held a staging loader entry the first pass did not see
    /// (`env_flags::CHANGED`); killed before their first instruction where
    /// the tier's rule refuses it. The agent reports the total.
    pub const ENV_CHANGED: u32 = 13;
    /// Lot 325 (R5): execs let through without their walk — the exec
    /// sensor's per-task buffer could not be made (the map full: a flood
    /// of execs in flight) and the exec is no protected target: judged on
    /// what needs no buffer, recorded. A protected target is refused and
    /// counted in [`LOST`]. The agent reports the total and signs a
    /// degradation while it moves.
    pub const LOST_OPEN: u32 = 14;
    /// Slots in the map.
    pub const SLOTS: u32 = 15;
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
        (env_flags::CHANGED, "changed_after_the_kernel_s_copy"),
        (env_flags::LOADER_CUT, "loader_value_cut"),
        (env_flags::PRELOAD_RELATIVE, "relative_loader_path"),
        (env_flags::LOADER_IRREGULAR, "irregular_loader_value"),
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

/// Lot 325 (the re-check of #546, R1): the entry an exec came through,
/// which says how the kernel reads `envp` from its register.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EnvpAbi {
    /// x86-64: the register whole, an array of 64-bit pointers.
    Native,
    /// The 32-bit entry (`int $0x80`, `sysenter`): the register's low 32
    /// bits — the ia32 stub casts it (`__SC_COMPAT_CAST`, `(unsigned
    /// int)regs->dx`) — an array of 32-bit pointers.
    Ia32,
    /// The x32 ABI: the register whole — the x32 stub passes `regs->dx`
    /// as an `unsigned long` (`SC_X86_64_REGS_TO_ARGS`, `__SC_DELOUSE`), and
    /// `compat_do_execve` reads the array at that address — an array of
    /// 32-bit pointers. Lot 322 truncated it as ia32's: a 64-bit caller of
    /// the x32 call put the real array above 4 GiB and a clean decoy at
    /// its low half, and the scan read the decoy.
    X32,
}

impl EnvpAbi {
    /// The array's entries are 32-bit pointers (zero-extended, as
    /// `compat_ptr` does).
    #[inline(always)]
    pub const fn compat_pointers(self) -> bool {
        !matches!(self, EnvpAbi::Native)
    }
}

/// Lot 322: where the exec's new environment is, from the syscall number
/// the exec entered with, and through which entry (lot 325: [`EnvpAbi`]).
/// `bprm_check_security` is reached from these six calls (and
/// `kernel_execve`, whose task has no user registers: the caller does not
/// ask): 11 and 358 are no native exec (`munmap`, none), 59 and 322 no
/// 32-bit one. `None`: not read (counted and recorded as
/// [`counter::ENV_UNREAD`]). The review of #547 (F3): the call is
/// `orig_ax`'s low 32 bits, as the kernel takes it — `entry_SYSCALL_64`
/// saves the whole `rax` as `orig_ax` and runs `(int)eax`, so an `execve`
/// entered with garbage in `rax`'s high half is an `execve` (it was "an
/// unknown call": not read, never refused).
#[inline(always)]
pub const fn exec_envp_reg(orig_ax: u64) -> Option<(EnvpReg, EnvpAbi)> {
    match orig_ax & 0xffff_ffff {
        NR_EXECVE => Some((EnvpReg::Dx, EnvpAbi::Native)),
        NR_EXECVEAT => Some((EnvpReg::R10, EnvpAbi::Native)),
        IA32_NR_EXECVE => Some((EnvpReg::Dx, EnvpAbi::Ia32)),
        IA32_NR_EXECVEAT => Some((EnvpReg::Si, EnvpAbi::Ia32)),
        X32_NR_EXECVE => Some((EnvpReg::Dx, EnvpAbi::X32)),
        X32_NR_EXECVEAT => Some((EnvpReg::R10, EnvpAbi::X32)),
        _ => None,
    }
}

/// `envp` as the kernel reads it from the register: an ia32 call's
/// truncated to its low 32 bits (a 64-bit caller of `int $0x80` may leave
/// the high half set: the kernel ignores it, so must the scan); a native
/// or an x32 call's whole (lot 325, R1: x32's is not truncated).
#[inline(always)]
pub const fn envp_value(reg: u64, abi: EnvpAbi) -> u64 {
    match abi {
        EnvpAbi::Ia32 => reg & 0xffff_ffff,
        EnvpAbi::Native | EnvpAbi::X32 => reg,
    }
}

/// Lot 322: the size of one entry of the `envp` array (8, or 4 for a
/// compat call): `8 - 4 * compat`, an arithmetic form the verifier bounds
/// to [4, 8] without splitting the scan's loop in two.
#[inline(always)]
pub const fn envp_stride(compat: u64) -> u64 {
    8 - 4 * (compat & 1)
}

/// Lot 325 (TOCTOU): bytes of the new image's environment the post-commit
/// check reads at once (its task entry's buffer, after the findings): a
/// string shorter than this is one read.
pub const ENV_REGION_READ: usize = 256;

/// Lot 325: the bytes of a task's `EXECPOL_ENV` entry (the findings, then
/// the post-commit check's read buffer).
pub const ENV_ENTRY_BYTES: usize = core::mem::size_of::<EnvStashRaw>()
    + ENV_REGION_READ
    + core::mem::size_of::<value_parse::ValueParse>()
    + 16;

/// Lot 325 (the re-check of #546, R2): the most variables an exec the
/// kernel accepts can carry. Its strings and its pointers share at most
/// 3/4 of `_STK_LIM` (6 MiB, `bprm_stack_limits`; a quarter of the stack
/// limit when that is lower), and each variable costs an 8-byte pointer
/// and at least one byte of string: 6 MiB / 9.
pub const KERNEL_ENVC_MAX: usize = (6 << 20) / 9;

/// Lot 325 (R2): the scan reads every variable, `ENV_STEP` per step of
/// the innermost loop, [`ENV_STEPS_MID`] steps per middle round and
/// [`ENV_ROUNDS`] rounds: [`ENV_SCAN_CAP`] in all, above
/// [`KERNEL_ENVC_MAX`]. It read the first 64 only: 64 padding variables
/// hid an `LD_PRELOAD` after them (no privilege, no race).
pub const ENV_STEP: usize = 64;
pub const ENV_STEPS_MID: usize = 128;
pub const ENV_ROUNDS: usize = 128;
pub const ENV_SCAN_CAP: usize = ENV_STEP * ENV_STEPS_MID * ENV_ROUNDS;

/// The review of #547 (F1): a loader variable's value judged entry by entry
/// as the loader parses it, one byte at a time (the kernel feeds it the
/// value in [`ENV_REGION_READ`]-byte reads, the state in the task's entry).
/// The staging check is lexical over the normalised path: `//` and `/./`
/// collapse, `..` removes the component before it, so `//tmp/x.so`,
/// `/./tmp/x.so` and `/var/../tmp/x.so` are `/tmp/x.so`; every entry is
/// judged wherever it starts in the value (it compared an entry's first
/// nine bytes, and only when they fitted in the 128-byte capture: 120
/// spaces then `/tmp/x` passed). Separators are the loader's: for
/// `LD_PRELOAD` the space, the colon and every other `isspace` byte (musl
/// splits on `isspace`); for `LD_AUDIT` the colon; for `LD_LIBRARY_PATH` the
/// colon and the semicolon. A symlink is not in the string: the mapping
/// check judges the file the loader maps.
pub mod value_parse {
    /// [`ValueParse::found`]: an entry under a staging directory.
    pub const STAGING: u32 = 1 << 0;
    /// An entry relative to the caller's directory (a `/` inside, not at
    /// its start); for `LD_LIBRARY_PATH`, any entry that is not absolute.
    pub const RELATIVE: u32 = 1 << 1;
    /// A bare name (no `/`): searched in the library path.
    pub const BARE: u32 = 1 << 2;
    /// The re-check of #547 (G1–G4): a control byte or a `$` in the value,
    /// or an empty `LD_LIBRARY_PATH` element ([`env_flags::LOADER_IRREGULAR`]).
    ///
    /// [`env_flags::LOADER_IRREGULAR`]: super::env_flags::LOADER_IRREGULAR
    pub const IRREGULAR: u32 = 1 << 3;

    /// The variable a value belongs to.
    pub const KIND_PRELOAD: u32 = 0;
    pub const KIND_AUDIT: u32 = 1;
    pub const KIND_LIBPATH: u32 = 2;

    /// [`ValueParse::st`]: inside an entry, the entry absolute, a `/` seen;
    /// and the last byte a separator (an empty `LD_LIBRARY_PATH` element at
    /// the value's end).
    const IN: u32 = 1 << 0;
    const ABS: u32 = 1 << 1;
    const SLASH: u32 = 1 << 2;
    const SEP: u32 = 1 << 3;

    /// The parse of one value: the first two components of the normalised
    /// path so far (their first eight bytes and length), the current one,
    /// the depth, the entry's state and what the value's entries showed.
    /// 48 bytes, no implicit padding.
    #[repr(C)]
    #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
    #[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
    pub struct ValueParse {
        pub c0: u64,
        pub c1: u64,
        pub cw: u64,
        pub c0len: u32,
        pub c1len: u32,
        pub clen: u32,
        pub depth: u32,
        pub st: u32,
        pub found: u32,
    }

    impl ValueParse {
        pub const fn zeroed() -> Self {
            Self {
                c0: 0,
                c1: 0,
                cw: 0,
                c0len: 0,
                c1len: 0,
                clen: 0,
                depth: 0,
                st: 0,
                found: 0,
            }
        }
    }

    const W_TMP: u64 = 0x70_6d74; // "tmp"
    const W_PROC: u64 = 0x636f_7270; // "proc"
    const W_VAR: u64 = 0x72_6176; // "var"
    const W_DEV: u64 = 0x76_6564; // "dev"
    const W_SHM: u64 = 0x6d_6873; // "shm"
    const W_FD: u64 = 0x6466; // "fd"
    const W_DOT: u64 = 0x2e; // "."
    const W_DOTDOT: u64 = 0x2e2e; // ".."

    /// Whether `b` ends an entry of a value of `kind`.
    #[inline(always)]
    pub const fn is_sep(kind: u32, b: u8) -> bool {
        match kind {
            KIND_PRELOAD => b == b':' || b == b' ' || (b >= 9 && b <= 13),
            KIND_AUDIT => b == b':',
            // glibc `":;"`, musl `":\n"`
            _ => b == b':' || b == b';' || b == b'\n',
        }
    }

    #[inline(always)]
    fn end_component(p: &mut ValueParse) {
        let w = p.cw;
        let l = p.clen;
        p.cw = 0;
        p.clen = 0;
        if l == 0 || (l == 1 && w == W_DOT) {
            return;
        }
        if l == 2 && w == W_DOTDOT {
            if p.depth > 0 {
                p.depth -= 1;
            }
            return;
        }
        if p.depth == 0 {
            p.c0 = w;
            p.c0len = l;
        } else if p.depth == 1 {
            p.c1 = w;
            p.c1len = l;
        }
        if p.depth < 255 {
            p.depth += 1;
        }
    }

    /// Whether the normalised absolute path of `p` is under a staging
    /// directory: `/tmp`, `/proc`, `/var/tmp`, `/dev/shm`, `/dev/fd` — for
    /// a file (a preload) something below them, for a directory (a library
    /// path) the directory itself too.
    #[inline(always)]
    fn staging(p: &ValueParse, kind: u32) -> bool {
        let d = if kind == KIND_LIBPATH {
            p.depth + 1
        } else {
            p.depth
        };
        let one = |w: u64, l: u32, want: u64, wl: u32| w == want && l == wl;
        (d >= 2 && (one(p.c0, p.c0len, W_TMP, 3) || one(p.c0, p.c0len, W_PROC, 4)))
            || (d >= 3
                && ((one(p.c0, p.c0len, W_VAR, 3) && one(p.c1, p.c1len, W_TMP, 3))
                    || (one(p.c0, p.c0len, W_DEV, 3)
                        && (one(p.c1, p.c1len, W_SHM, 3) || one(p.c1, p.c1len, W_FD, 2)))))
    }

    /// The end of an entry (a separator, or the value's end).
    #[inline(always)]
    pub fn end_entry(p: &mut ValueParse, kind: u32) {
        if p.st & IN == 0 {
            return;
        }
        end_component(p);
        if p.st & ABS != 0 {
            if staging(p, kind) {
                p.found |= STAGING;
            }
        } else if kind == KIND_LIBPATH || p.st & SLASH != 0 {
            p.found |= RELATIVE;
        } else {
            p.found |= BARE;
        }
        p.st = 0;
        p.c0 = 0;
        p.c1 = 0;
        p.c0len = 0;
        p.c1len = 0;
        p.depth = 0;
    }

    /// The re-check of #547 (G1–G4): any byte of a value — a control byte
    /// or a `$` makes it [`IRREGULAR`].
    #[inline(always)]
    pub fn odd(p: &mut ValueParse, b: u8) {
        if b < 0x20 || b == 0x7f || b == b'$' {
            p.found |= IRREGULAR;
        }
    }

    /// A separator of a value of `kind`: the entry before it ends; in an
    /// `LD_LIBRARY_PATH`, a separator with no entry before it is an empty
    /// element — the caller's directory (glibc's `fillin_rpath`).
    #[inline(always)]
    pub fn sep(p: &mut ValueParse, kind: u32) {
        if kind == KIND_LIBPATH && p.st & IN == 0 {
            p.found |= IRREGULAR;
        }
        end_entry(p, kind);
        p.st |= SEP;
    }

    /// A byte `b` that is no separator: the start of an entry, if one is
    /// not open (absolute when it is a `/`).
    #[inline(always)]
    pub fn begin(p: &mut ValueParse, b: u8) {
        p.st &= !SEP;
        if p.st & IN == 0 {
            p.st |= IN | if b == b'/' { ABS } else { 0 };
        }
    }

    /// The value's end (its NUL): the last entry judged; an `LD_LIBRARY_PATH`
    /// that ends with a separator ends with an empty element.
    #[inline(always)]
    pub fn end_value(p: &mut ValueParse, kind: u32) {
        if kind == KIND_LIBPATH && p.st & SEP != 0 {
            p.found |= IRREGULAR;
        }
        end_entry(p, kind);
    }

    /// A `/` inside an entry: the component before it ends.
    #[inline(always)]
    pub fn slash(p: &mut ValueParse) {
        p.st |= SLASH;
        end_component(p);
    }

    /// Any other byte of a component.
    #[inline(always)]
    pub fn push(p: &mut ValueParse, b: u8) {
        if p.clen < 8 {
            p.cw |= (b as u64) << (8 * p.clen);
        }
        if p.clen < 255 {
            p.clen += 1;
        }
    }

    /// One byte of a value of `kind` (not its NUL: the value's end is
    /// [`end_value`]). The eBPF program runs the same steps, its separator
    /// and `/` ones in global functions (`agent-ebpf/src/execpol.rs`,
    /// `nn_env_chunk`).
    #[inline(always)]
    pub fn byte(p: &mut ValueParse, kind: u32, b: u8) {
        odd(p, b);
        if is_sep(kind, b) {
            sep(p, kind);
            return;
        }
        begin(p, b);
        if b == b'/' {
            slash(p);
            return;
        }
        push(p, b);
    }

    /// A whole value (host side: tests, the userland re-check).
    pub fn judge(kind: u32, value: &[u8]) -> u32 {
        let mut p = ValueParse::zeroed();
        for &b in value {
            if b == 0 {
                break;
            }
            byte(&mut p, kind, b);
        }
        end_value(&mut p, kind);
        p.found
    }
}

/// The review of #547 (F7): a loader variable's value is judged whole, read
/// [`ENV_REGION_READ`] bytes at a time, up to this many reads (about 4 KiB);
/// past it, `LOADER_CUT`.
pub const ENV_VALUE_READS: usize = 16;
/// The review of #547 (F8): the judged names (`LD_*`, `GLIBC_TUNABLES`, the
/// history ones) read whole per exec; past it the scan is not finished
/// (`TRUNCATED`). No legitimate environment carries that many.
pub const ENV_JUDGED_MAX: u32 = 64;
/// The review of #547 (F8): the post-commit check reads at most this many
/// rounds, each of at most `ENV_STEPS_MID + ENV_JUDGED_MAX` steps of
/// [`ENV_STEP`] reads (98,304 reads of the strings at most, with
/// preemption off), and the judged names' values; past them, `TRUNCATED`.
pub const ENV_COMMIT_ROUNDS: usize = 8;

/// Lot 325 (R2): whether the first eight bytes of a variable (`w0`, little
/// endian) start one of the names the scan reads whole — the loader
/// variables, `GLIBC_TUNABLES`, the history ones. Every other variable
/// costs its pointer and these eight bytes.
#[inline(always)]
pub const fn env_name_wanted(w0: u64) -> bool {
    w0 == u64::from_le_bytes(*b"LD_PRELO")
        || w0 == u64::from_le_bytes(*b"LD_AUDIT")
        || w0 == u64::from_le_bytes(*b"LD_LIBRA")
        || w0 == u64::from_le_bytes(*b"GLIBC_TU")
        || w0 == u64::from_le_bytes(*b"HISTFILE")
        || w0 == u64::from_le_bytes(*b"HISTSIZE")
        || w0 == u64::from_le_bytes(*b"HISTCONT")
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
        assert_eq!(
            env_names(env_flags::CHANGED),
            ["changed_after_the_kernel_s_copy"]
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
        assert_eq!(exec_envp_reg(59), Some((EnvpReg::Dx, EnvpAbi::Native)));
        assert_eq!(exec_envp_reg(322), Some((EnvpReg::R10, EnvpAbi::Native)));
        assert_eq!(exec_envp_reg(11), Some((EnvpReg::Dx, EnvpAbi::Ia32)));
        assert_eq!(exec_envp_reg(358), Some((EnvpReg::Si, EnvpAbi::Ia32)));
        assert_eq!(
            exec_envp_reg(0x4000_0000 | 520),
            Some((EnvpReg::Dx, EnvpAbi::X32))
        );
        assert_eq!(
            exec_envp_reg(0x4000_0000 | 545),
            Some((EnvpReg::R10, EnvpAbi::X32))
        );
        // kernel_execve's zeroed registers, a negative (no call), x32's
        // numbers without the bit (no native call), a native call that
        // never execs, a native number with the x32 bit
        for other in [0, u64::MAX, 520, 545, 9, 0x4000_0000 | 59] {
            assert_eq!(exec_envp_reg(other), None, "{other:#x}");
        }
        assert!(!EnvpAbi::Native.compat_pointers());
        assert!(EnvpAbi::Ia32.compat_pointers());
        assert!(EnvpAbi::X32.compat_pointers());
        assert_eq!(envp_stride(0), 8);
        assert_eq!(envp_stride(1), 4);
        assert_eq!(envp_stride(3), 4);
    }

    /// The review of #547 (F3): the kernel takes the call from `orig_ax`'s
    /// low 32 bits (`entry_SYSCALL_64` saves `rax` whole and runs
    /// `(int)eax`): an `execve` entered with garbage in `rax`'s high half
    /// is an `execve`, and its environment is read. It was "an unknown
    /// call": not read, never refused (the reviewer's probe).
    #[test]
    fn an_exec_entered_with_garbage_in_rax_s_high_half_is_read() {
        assert_eq!(
            exec_envp_reg((1u64 << 32) | 59),
            Some((EnvpReg::Dx, EnvpAbi::Native))
        );
        assert_eq!(
            exec_envp_reg(0xdead_0000_0000_0142),
            Some((EnvpReg::R10, EnvpAbi::Native))
        );
        assert_eq!(
            exec_envp_reg(0xdead_0000_4000_0208),
            Some((EnvpReg::Dx, EnvpAbi::X32))
        );
        assert_eq!(
            exec_envp_reg(0xffff_ffff_0000_000b),
            Some((EnvpReg::Dx, EnvpAbi::Ia32))
        );
        // still nothing for what is no exec in its low half
        assert_eq!(exec_envp_reg((1u64 << 32) | 9), None);
    }

    /// Lot 325 (the re-check of #546, R1): the kernel reads an ia32 exec's
    /// `envp` from the register's low half (the ia32 stub's `(unsigned
    /// int)` cast), a native or an x32 exec's from the register whole (the
    /// x32 stub passes it as an `unsigned long`). Lot 322 truncated x32's
    /// too: an x32 `execve` from a 64-bit caller with the real array at
    /// `(1 << 32) | LO` and a clean decoy at `LO` loaded the preload, and
    /// the scan read the decoy (the host PoC `x32hi.c`).
    #[test]
    fn an_x32_exec_s_envp_is_the_register_whole_and_an_ia32_one_its_low_half() {
        assert_eq!(
            envp_value(0xdead_beef_0040_1000, EnvpAbi::Ia32),
            0x0040_1000
        );
        assert_eq!(
            envp_value(0x0000_0001_0040_1000, EnvpAbi::X32),
            0x0000_0001_0040_1000
        );
        assert_eq!(
            envp_value(0x7ffd_0040_1000, EnvpAbi::Native),
            0x7ffd_0040_1000
        );
    }

    /// Lot 325 (the re-check of #546, R2): the scan's bound is above any
    /// environment the kernel accepts — 64 padding variables hid an
    /// `LD_PRELOAD` after them — and its three loops multiply to it.
    #[test]
    fn the_scan_reads_more_variables_than_the_kernel_accepts() {
        assert_eq!(KERNEL_ENVC_MAX, 699_050);
        assert_eq!(ENV_SCAN_CAP, ENV_STEP * ENV_STEPS_MID * ENV_ROUNDS);
        // (through `black_box`: a runtime check, which a mutant of the
        // constants fails as a test, not as a build)
        let cap = std::hint::black_box(ENV_SCAN_CAP);
        assert!(cap > KERNEL_ENVC_MAX, "{cap}");
        // the innermost step's pointers fit one probe of 512 bytes
        assert!(std::hint::black_box(ENV_STEP) * 8 <= 512);
    }

    /// Lot 325 (R2): the names the scan reads whole, by their first eight
    /// bytes; every other variable costs its pointer and those bytes.
    #[test]
    fn the_scan_reads_whole_only_the_names_it_judges() {
        let w = |s: &[u8]| {
            let mut b = [0u8; 8];
            let n = s.len().min(8);
            b[..n].copy_from_slice(&s[..n]);
            u64::from_le_bytes(b)
        };
        for yes in [
            &b"LD_PRELOAD=/tmp/x.so"[..],
            b"LD_AUDIT=/tmp/a.so",
            b"LD_LIBRARY_PATH=/tmp",
            b"GLIBC_TUNABLES=glibc.x=1",
            b"HISTFILE=/dev/null",
            b"HISTFILESIZE=0",
            b"HISTSIZE=0",
            b"HISTCONTROL=ignorespace",
        ] {
            assert!(env_name_wanted(w(yes)), "{}", String::from_utf8_lossy(yes));
        }
        for no in [
            &b"PATH=/usr/bin"[..],
            b"LD_BIND_NOW=1",
            b"LD_PREL",
            b"HOME=/root",
            b"",
            b"=",
            b"ld_preload=/tmp/x.so",
        ] {
            assert!(!env_name_wanted(w(no)), "{}", String::from_utf8_lossy(no));
        }
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
