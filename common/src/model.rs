//! Userland event/verdict model.
//!
//! These are the rich, owned types the daemon and CLI manipulate.
//! Sensors convert raw kernel events (see [`crate::wire`]) into the
//! variants of [`Event`]; the decision engine produces a [`Verdict`]
//! describing what response the executors should run.

use alloc::string::String;
use serde::{Deserialize, Serialize};

use crate::dns_qname::{decode_dns_qname, qname_wire_end};
use crate::wire::{
    DnsQueryRaw, ExecCheckRaw, FileOpenRaw, FsProtectDenialRaw, ProcessSpawnRaw, TcpConnectRaw,
    ADDR_LEN, FS_OP_BPF_LINK, FS_OP_BPF_MAP, FS_OP_CREATE, FS_OP_IOCTL, FS_OP_KEXEC, FS_OP_LINK,
    FS_OP_MKDIR, FS_OP_MKNOD, FS_OP_PTRACE, FS_OP_READ, FS_OP_RENAME, FS_OP_RMDIR, FS_OP_SETATTR,
    FS_OP_SIGNAL, FS_OP_SYMLINK, FS_OP_UNLINK, FS_OP_WRITE, FS_OP_XATTR,
};

/// Serde default of `Event::CanaryTripped::first_trip`.
fn canary_first_trip_default() -> bool {
    true
}

/// Canonical event emitted by a sensor.
///
/// Tappa 4 turns the placeholder variants into rich data carriers,
/// each populated from a corresponding `*Raw` Pod struct in
/// [`crate::wire`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    /// Post-exec event (sched_process_exec tracepoint).
    ProcessSpawn {
        pid: u32,
        ppid: u32,
        uid: u32,
        gid: u32,
        comm: String,
        filename: String,
        timestamp_ns: u64,
        /// Tappa 10.6: argument vector (decoded from the NUL-separated
        /// wire blob). Empty until D2 wires the BPF read, and on
        /// older-agent / mixed-fleet serialized records (`serde` default).
        #[serde(default)]
        argv: Vec<String>,
        /// Tappa 10.6: resolved parent `comm` (empty until D2 / older
        /// records).
        #[serde(default)]
        parent_comm: String,
        /// Tappa 10.6: parent `start_time` — PID-reuse-safe ancestry key
        /// for the correlation engine (0 until D2 / older records).
        #[serde(default)]
        parent_start_ns: u64,
        /// External audit POS-003: the process's own `start_time` (its
        /// fork; exec keeps it), on the clock of `timestamp_ns`. 0 on
        /// older records.
        #[serde(default)]
        start_ns: u64,
        /// Cluster 15.3 / R011: BPF read `parent->flags & PF_KTHREAD`
        /// at exec time. `true` iff the parent was a kernel thread —
        /// non-forgeable from userspace (no prctl / unshare / ns trick
        /// can flip this bit). `false` covers BOTH "real userspace
        /// parent" AND "BPF read failed" — R011 treats both identically
        /// (fail-secure FIRE) so a mis-validated offset / older BPF /
        /// flag-unset event never silently exempts. `#[serde(default)]`
        /// preserves backward compat with pre-cluster-15.3 serialized
        /// records (they decode as `false` → fail-secure).
        #[serde(default)]
        parent_is_kthread: bool,
        /// Tappa 10.9 step 2: the file the caller named, as the kernel
        /// opened it (review 61). Empty in tracepoint mode.
        #[serde(default)]
        exe: ExeIdentity,
        /// External audit EBPF-021: `argv` is not the whole command line —
        /// the kernel's was longer than `wire::ARGV_LEN - 1` bytes (the
        /// last argument kept may itself be cut), or it could not be read
        /// (`argv` empty). A rule that decides on an argument must not
        /// read its absence as "not there". `false` on older records and
        /// from an older eBPF object ("not known to be cut").
        #[serde(default)]
        argv_truncated: bool,
        /// External audit EBPF-021: `filename` (the caller's string) was
        /// cut at `wire::FILENAME_LEN` bytes; it names no path (a `..`
        /// past the cut may lead anywhere). `false` on older records.
        #[serde(default)]
        filename_truncated: bool,
        /// Lab PR 224 (CM-03): the new image's standard streams and its
        /// parent's, as the kernel found them at the exec: which are inet
        /// sockets, connected out or not, and to which peer. Unread
        /// (`read: false`) on older records and older eBPF objects.
        #[serde(default)]
        stdio: StdioSockets,
    },
    /// File open event (LSM `file_open`).
    FileOpen {
        pid: u32,
        uid: u32,
        gid: u32,
        comm: String,
        filename: String,
        flags: u32,
        timestamp_ns: u64,
        /// External audit POS-004: `filename` is the string the caller
        /// passed, read from its memory at syscall entry (tracepoint mode),
        /// before any permission check and unresolved — not the path the
        /// kernel opened (LSM mode). `false` on older records.
        #[serde(default)]
        path_from_user: bool,
        /// External audit SNS-005: why the LSM file-open sensor emitted the
        /// open (`wire::open_sensor::open_reason` bits: the kernel's class of
        /// the file, by inode). Consumers use it when `filename` cannot be
        /// compared with a host path (an unplaced mount root, a cut or
        /// unread component). 0 in tracepoint mode and on older records.
        #[serde(default)]
        kernel_class: u32,
    },
    /// Tappa 10.9 step 1: one process crossed the mass-write threshold
    /// (`OPEN_MASS_WRITE_MIN` write-opens within the window), counted in
    /// the kernel by the file-open sensor on LSM `file_open`. Replaces
    /// counting every write `FileOpen` in userland; carve-outs (sysfs,
    /// procfs, …, `/run/systemd`, the writer's own runtime dir) are
    /// applied in the kernel.
    MassWrite {
        pid: u32,
        uid: u32,
        comm: String,
        /// Write-opens in the window when the threshold was crossed.
        count: u32,
        /// The write-open that crossed it (absolute path when resolved).
        filename: String,
        timestamp_ns: u64,
        /// External audit POS-002: the threshold crossed is the one of
        /// write-opens of files that existed before the open (no
        /// `FMODE_CREATED`) — rewriting files in place, the shape of
        /// encryption — not only of write-opens.
        #[serde(default)]
        overwrites: bool,
        /// External audit EBPF-011: the overwrites crossed the threshold of
        /// the writer's cgroup — its processes together, each below its own
        /// — and `count` is the cgroup's overwrites in the window.
        #[serde(default)]
        cgroup_window: bool,
    },
    /// Pre-exec event: one per binfmt pass of LSM `bprm_check_security`
    /// (Tappa 10.9 step 2), or one per `execve` in tracepoint mode.
    ExecCheck {
        pid: u32,
        ppid: u32,
        uid: u32,
        comm: String,
        /// The caller's string (`bprm->filename`).
        filename: String,
        timestamp_ns: u64,
        /// The file this pass examines (empty in tracepoint mode).
        #[serde(default)]
        exe: ExeIdentity,
    },
    /// Kernel module load (BUG-034) — BPF-LSM `kernel_read_file`
    /// (finit_module) / `kernel_load_data` (init_module). The LOAD is
    /// the rootkit-LKM chokepoint that FIM-008 (file path) + R011 (tool
    /// exec) both miss. Scored by R018.
    ModuleLoad {
        method: ModuleLoadMethod,
        loader_pid: u32,
        loader_uid: u32,
        loader_comm: String,
        parent_comm: String,
        /// Non-forgeable `PF_KTHREAD` on the loader's real parent — a
        /// kernel-driven (boot / hot-plug) load. R018 exempts it.
        #[serde(default)]
        parent_is_kthread: bool,
        /// Reconstructed source `.ko` path (finit_module). `None` for
        /// init_module (legacy buffer load — no file).
        path: Option<String>,
        timestamp_ns: u64,
    },
    /// A `bpf()` syscall of interest by a process that is not the agent or
    /// the watchdog (LSM hook `bpf`): program load, attach, link create /
    /// detach, handle-by-id on the agent's own objects. The BPF ecosystem is
    /// both the agent's tool and an attacker's (rootkits, map tampering);
    /// scored by NN-L-BPF-001/002. Denials of writes to the agent's maps
    /// travel as `FsProtectDenial` with `FS_OP_BPF_MAP`.
    BpfSyscall {
        pid: u32,
        uid: u32,
        comm: String,
        /// uapi `bpf_cmd` or a synthetic `BPF_CMD_*` value.
        cmd: u32,
        /// Command-specific argument (see `BpfSyscallRaw::arg`).
        arg: u32,
        timestamp_ns: u64,
    },
    /// io_uring ring created or used (tracepoints `io_uring_create`,
    /// `io_uring_submit_{req,sqe}`), aggregated per pid in kernel: the
    /// asynchronous I/O channel syscall-centric sensors miss — file and
    /// network operations queued through a ring never pass through
    /// `openat`/`connect`/`sendto`. Scored by NN-L-IOU-001/002.
    IoUring {
        /// `true` = ring creation; `false` = activity on an existing ring.
        created: bool,
        pid: u32,
        uid: u32,
        comm: String,
        /// Opcode classes seen since the pid's first submission
        /// (`IOURING_CLASS_*` bitmap); ring `flags` for a creation.
        classes: u32,
        /// Submissions since the previous record; `sq_entries` for a creation.
        count: u32,
        /// Last `IORING_OP_*` number.
        last_opcode: u8,
        /// Submitted by the SQPOLL kernel thread on behalf of the process.
        sq_thread: bool,
        timestamp_ns: u64,
    },
    /// Outbound TCP connect attempt (kprobe `tcp_v[46]_connect`).
    TcpConnect {
        pid: u32,
        uid: u32,
        comm: String,
        family: u8,
        src_addr: [u8; ADDR_LEN],
        src_port: u16,
        dst_addr: [u8; ADDR_LEN],
        dst_port: u16,
        timestamp_ns: u64,
    },
    /// DNS query (kprobe `udp_sendmsg` filtered to dest port 53).
    DnsQuery {
        pid: u32,
        uid: u32,
        comm: String,
        /// FP-3 (NN-L-NET-004/-005/-014 originator attribution):
        /// kernel-resolved `/proc/<pid>/exe` of the UDP/53 *sender*,
        /// populated best-effort in
        /// [`crate`]'s `pump_dns_query` (mirrors the FIM drain's
        /// `modifier_exe` — NEVER `comm`, which is
        /// `prctl(PR_SET_NAME)`-spoofable and here would grant a forged
        /// resolver kill-immunity). `None` on a resolve miss (sender
        /// already exited / link unreadable) → the attribution layer
        /// treats a `None` sender as a non-forwarder, failing toward
        /// today's behaviour. `#[serde(default)]` keeps pre-FP-3
        /// serialized `DnsQuery` records deserialisable.
        #[serde(default)]
        exe: Option<String>,
        query_name: String,
        query_type: u16,
        dns_server: [u8; ADDR_LEN],
        family: u8,
        timestamp_ns: u64,
        /// Tappa 10.9 step 3: the name does not end inside the bytes the
        /// socket-buffer sensor could read — the rest is in page fragments
        /// (a corked send, UDP GSO, zero copy) or the datagram is not a DNS
        /// query. `query_name` holds the part that was read. Resolvers send
        /// a query in one piece; NET-004 records it. Always `false` in
        /// `--dns-sensor sendmsg` mode.
        #[serde(default)]
        qname_partial: bool,
    },
    /// Tappa 7 inode-protection LSM hook denied a modification of a
    /// protected filesystem object. By construction this means
    /// someone (often root) attempted to delete, rename, chmod,
    /// chown, or `chattr` the agent's own state directory.
    FsProtectDenial {
        pid: u32,
        uid: u32,
        comm: String,
        target_dev: u64,
        target_ino: u64,
        operation: FsProtectOperation,
        timestamp_ns: u64,
    },
    /// Tappa 9 (C4) — file-integrity drift detected by the
    /// observe-only FIM LSM hooks. The drain loop has already
    /// re-hashed the target + diffed against the baseline DB;
    /// emission here means the file actually changed. C5 rule
    /// matchers consume this variant.
    Fim(crate::wire::FimEvent),
    /// Tappa 9.5 (K3) — canary token access detected by the
    /// inline detector filter. The filter has already
    /// (a) verified the (dev,ino) / exe path / port matches a
    /// deployed canary in the K2 registry, (b) marked the
    /// canary as `tripped` (idempotent per §12 Q2), and
    /// (c) appended a `CanaryAccessEntry` to the chained
    /// `canary_access.jsonl` access log. The K5 rule layer
    /// (NN-L-CANARY-001..004) consumes this variant —
    /// always Critical + KillProcessTree + posture→COMBAT
    /// by design §6 zero-FP contract.
    ///
    /// **Precedence over `Event::Fim`** (§12 Q9 OPTION B
    /// inline-filter lock-in): when the detector returns
    /// `Some(CanaryTripped)` for an inbound `Event::Fim` /
    /// `Event::ProcessSpawn`, `main::process_event` REPLACES
    /// the source event with the canary event AND skips the
    /// FIM rule layer — so an NN-L-CANARY-004 trip on a
    /// credential canary never double-fires alongside an
    /// NN-L-FIM-011 read alert.
    CanaryTripped {
        /// Per-canary stable ID from the K2 registry (`SHA-256
        /// (name || ":" || deployed_at_unix)[..16]` rendered as
        /// 32 hex chars).
        canary_id: String,
        /// Operator-supplied human-readable canary name.
        canary_name: String,
        /// Kind of canary that tripped — drives K5 rule
        /// selection (NN-L-CANARY-001 File / -002 Process /
        /// -003 Network / -004 Credential).
        canary_type: CanaryTypeTag,
        /// What the agent observed the accessor doing.
        access_kind: CanaryAccessKind,
        /// Process triple at access time. The K5 rules use
        /// these to dispatch the `KillProcessTree` response.
        accessor_pid: u32,
        accessor_uid: u32,
        accessor_comm: alloc::string::String,
        /// `/proc/<pid>/exe` of the accessor if userland
        /// could resolve it at detect time. Best-effort.
        accessor_exe: Option<alloc::string::String>,
        /// Monotonic-clock ns from the source event
        /// (`Event::Fim::timestamp_ns` or
        /// `Event::ProcessSpawn::timestamp_ns`). Preserved
        /// across the canary-precedence remap so the trip
        /// record's wall-clock context isn't lost.
        timestamp_ns: u64,
        /// External audit DEC-004: the first access to this canary since it
        /// was deployed (design §7.5, §12 Q2). Only the first one is a trip
        /// the K5 rules respond to; every access is in the signed
        /// `canary_access.jsonl` chain all the same. A record written before
        /// the field existed reads as a first trip.
        #[serde(default = "canary_first_trip_default")]
        first_trip: bool,
    },
    /// Tappa 10 (N3) — userland-finalised network flow. The
    /// agent's `net::flow_tracker` stitches the BPF-side
    /// connect kprobe + tcp_close fexit (N2) into one
    /// [`crate::wire::NetFlowEvent`] per closed flow, OR
    /// emits one per outbound UDP send. N6 rules
    /// (NN-L-NET-001..009) consume this variant.
    NetFlow(crate::wire::NetFlowEvent),
    /// Tappa 10 (N2) — TCP listener observation (kprobe on
    /// `inet_csk_listen_start`). Emitted unconditionally per
    /// §13 Q6 (forensic-visibility lock-in); the rule layer
    /// (NN-L-NET-006) applies the operator-tunable comm + port
    /// allowlist filter.
    NetListener(crate::wire::NetListenerEvent),
    /// Review 78: DNS queries the kernel held back from one process (its
    /// DNS budget ran out) or from its user (`uid_level`: the user's
    /// budget ran out, across processes). Carried by the process's next
    /// DNS record, so it is attributed and never silent: a process that
    /// floods DNS to keep its own tunnel queries out of the records is
    /// itself flagged (NN-L-NET-020).
    DnsFlood {
        pid: u32,
        uid: u32,
        comm: String,
        /// Kernel-resolved `/proc/<pid>/exe` (best-effort), as for
        /// `DnsQuery`.
        #[serde(default)]
        exe: Option<String>,
        held: u32,
        uid_level: bool,
        timestamp_ns: u64,
    },
    /// External audit EBPF-013: records the kernel held back from one
    /// process (its record budget for `source` ran out) or from its user
    /// (`uid_level`: the user's budget ran out, across processes). Carried
    /// by the process's next record of the same sensor, so the loss is
    /// attributed: a process that loops `listen()` or `io_uring_setup()`
    /// to push another process's records out of the ring is itself
    /// flagged (NN-L-NET-021).
    SensorFlood {
        source: FloodSource,
        pid: u32,
        uid: u32,
        comm: String,
        /// Kernel-resolved `/proc/<pid>/exe` (best-effort).
        #[serde(default)]
        exe: Option<String>,
        held: u32,
        uid_level: bool,
        timestamp_ns: u64,
    },
    /// Lab PR 219 — an exploit post-condition found by the guard at the
    /// system-call boundary (`raw_syscalls/sys_enter`, `sys_exit` and the
    /// `commit_creds` / `switch_task_namespaces` / `set_fs_root` hooks): a
    /// task that was not fully privileged gained credentials, or left its
    /// namespaces or its root, with no legitimate mechanism for that call.
    /// Recorded by NN-L-EPG-001 (credentials) and NN-L-EPG-002 (namespaces
    /// and root) outside the engine: in enforce mode the kernel already
    /// sent `SIGKILL` before the task returned to user mode.
    ExploitPostcondition {
        kind: EpgKind,
        /// Enforce mode: `SIGKILL` was sent at the hook (`false` in detect
        /// mode, and when the signal could not be sent: `kill_failed`).
        killed: bool,
        #[serde(default)]
        kill_failed: bool,
        /// Thread group and thread.
        pid: u32,
        tid: u32,
        /// Host real uid at the snapshot.
        uid: u32,
        comm: String,
        /// The call the change happened in, by number in its ABI.
        abi: SyscallAbi,
        syscall: u32,
        /// `epg::mech` bits seen during the call.
        mechanisms: u32,
        before: CredView,
        after: CredView,
        /// `ns.inum` before → after (0 when not read).
        mnt_ns: (u32, u32),
        pid_ns: (u32, u32),
        net_ns: (u32, u32),
        /// Another `struct cred` (a replaced pointer) rather than a write
        /// into the same one.
        cred_replaced: bool,
        root_changed: bool,
        fs_changed: bool,
        /// Found at the next `sys_enter`: the call never reached `sys_exit`.
        exit_bypassed: bool,
        timestamp_ns: u64,
        /// Lab fault injection (`debug-trigger` build): nothing changed.
        #[serde(default)]
        injected: bool,
        /// Which guard caught it (lite, the default, or strict).
        #[serde(default)]
        variant: GuardVariant,
        /// Where: a system-call boundary (strict), a mechanism hook, or a
        /// use point (lite: `capable`, exec, `file_open`).
        #[serde(default)]
        caught_at: CatchPoint,
        /// Lite, degraded evidence: the task's record was lost (task map
        /// eviction) and re-taken here, and what it holds (`after`, equal
        /// to `before`) holds privilege no mechanism is known to have
        /// given. Recorded only, never refused or killed.
        #[serde(default)]
        baseline_lost: bool,
        /// Lite: `before` is a snapshot re-taken after a lost record (here
        /// or earlier), not the one fork and the mechanisms kept.
        #[serde(default)]
        rebaselined: bool,
    },
}

/// Lab PR 219: what the exploit post-condition guard found (`epg::kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpgKind {
    CredNoMechanism,
    CredFromSyscall,
    NsNoMechanism,
    NsFromSyscall,
    RootNoMechanism,
    RootFromSyscall,
    FsSwapped,
    CredBetweenSyscalls,
    CredOutsideSyscall,
    Unknown(u8),
}

impl EpgKind {
    pub fn from_wire(k: u8) -> Self {
        use crate::epg::kind as k_;
        match k {
            k_::CRED_NO_MECHANISM => Self::CredNoMechanism,
            k_::CRED_FROM_SYSCALL => Self::CredFromSyscall,
            k_::NS_NO_MECHANISM => Self::NsNoMechanism,
            k_::NS_FROM_SYSCALL => Self::NsFromSyscall,
            k_::ROOT_NO_MECHANISM => Self::RootNoMechanism,
            k_::ROOT_FROM_SYSCALL => Self::RootFromSyscall,
            k_::FS_SWAPPED => Self::FsSwapped,
            k_::CRED_BETWEEN_SYSCALLS => Self::CredBetweenSyscalls,
            k_::CRED_OUTSIDE_SYSCALL => Self::CredOutsideSyscall,
            other => Self::Unknown(other),
        }
    }

    /// Credentials (NN-L-EPG-001, T1068) rather than namespaces or root
    /// (NN-L-EPG-002, T1611). An unknown byte counts as credentials: the
    /// stronger rule records it.
    pub fn is_credential(&self) -> bool {
        !matches!(
            self,
            Self::NsNoMechanism
                | Self::NsFromSyscall
                | Self::RootNoMechanism
                | Self::RootFromSyscall
                | Self::FsSwapped
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::CredNoMechanism => "cred_no_mechanism",
            Self::CredFromSyscall => "cred_from_syscall",
            Self::NsNoMechanism => "ns_no_mechanism",
            Self::NsFromSyscall => "ns_from_syscall",
            Self::RootNoMechanism => "root_no_mechanism",
            Self::RootFromSyscall => "root_from_syscall",
            Self::FsSwapped => "fs_swapped",
            Self::CredBetweenSyscalls => "cred_between_syscalls",
            Self::CredOutsideSyscall => "cred_outside_syscall",
            Self::Unknown(_) => "unknown",
        }
    }

    /// One line for the verdict's reasoning.
    pub fn describe(&self) -> &'static str {
        match self {
            Self::CredNoMechanism => {
                "credentials gained with no commit_creds during the call (a write into the \
                 task's struct cred, or its pointer replaced)"
            }
            Self::CredFromSyscall => {
                "commit_creds gave privileges on behalf of a system call that never changes \
                 them (the commit_creds(prepare_kernel_cred(...)) of a kernel exploit)"
            }
            Self::NsNoMechanism => "namespaces replaced with no switch_task_namespaces",
            Self::NsFromSyscall => {
                "switch_task_namespaces on behalf of a system call that never switches them"
            }
            Self::RootNoMechanism => {
                "filesystem root changed with no set_fs_root, no pivot_root and no root change \
                 elsewhere on the host"
            }
            Self::RootFromSyscall => {
                "set_fs_root on behalf of a system call that never sets a root"
            }
            Self::FsSwapped => "the task's fs_struct replaced outside unshare(CLONE_FS)",
            Self::CredBetweenSyscalls => {
                "credentials gained between two system calls, or in a call that never reached \
                 its exit (an exploit's return path)"
            }
            Self::CredOutsideSyscall => {
                "commit_creds gave privileges outside any system call of a task that was not \
                 fully privileged"
            }
            Self::Unknown(_) => "an anomaly this agent does not know (newer eBPF object)",
        }
    }
}

/// Lab PR 219: which guard ran ([`Event::ExploitPostcondition`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardVariant {
    #[default]
    Lite,
    Strict,
}

impl GuardVariant {
    pub fn from_wire(v: u8) -> Self {
        if v == crate::epg::variant::STRICT {
            Self::Strict
        } else {
            Self::Lite
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Lite => "lite",
            Self::Strict => "strict",
        }
    }
}

/// Lab PR 219: where the guard caught it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatchPoint {
    SysEnter,
    SysExit,
    CommitCreds,
    SwitchNs,
    SetFsRoot,
    Capable,
    Exec,
    FileOpen,
    #[default]
    Unknown,
}

impl CatchPoint {
    pub fn from_wire(p: u8) -> Self {
        use crate::epg::point as p_;
        match p {
            p_::SYS_ENTER => Self::SysEnter,
            p_::SYS_EXIT => Self::SysExit,
            p_::COMMIT_CREDS => Self::CommitCreds,
            p_::SWITCH_NS => Self::SwitchNs,
            p_::SET_FS_ROOT => Self::SetFsRoot,
            p_::CAPABLE => Self::Capable,
            p_::EXEC => Self::Exec,
            p_::FILE_OPEN => Self::FileOpen,
            _ => Self::Unknown,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SysEnter => "sys_enter",
            Self::SysExit => "sys_exit",
            Self::CommitCreds => "commit_creds",
            Self::SwitchNs => "switch_task_namespaces",
            Self::SetFsRoot => "set_fs_root",
            Self::Capable => "capable()",
            Self::Exec => "exec (bprm_check_security)",
            Self::FileOpen => "file_open",
            Self::Unknown => "unknown",
        }
    }
    /// A lite use point: in enforce the use itself was refused.
    pub fn is_use_point(&self) -> bool {
        matches!(self, Self::Capable | Self::Exec | Self::FileOpen)
    }
}

/// Lab PR 219: the system-call ABI of [`Event::ExploitPostcondition`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyscallAbi {
    X64,
    Ia32,
    X32,
    /// No system call (task work, interrupt context).
    None,
}

impl SyscallAbi {
    pub fn from_wire(a: u8) -> Self {
        match a {
            crate::epg::abi::X64 => Self::X64,
            crate::epg::abi::IA32 => Self::Ia32,
            crate::epg::abi::X32 => Self::X32,
            _ => Self::None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::X64 => "x86_64",
            Self::Ia32 => "i386",
            Self::X32 => "x32",
            Self::None => "none",
        }
    }

    fn wire(&self) -> u8 {
        match self {
            Self::X64 => crate::epg::abi::X64,
            Self::Ia32 => crate::epg::abi::IA32,
            Self::X32 => crate::epg::abi::X32,
            Self::None => crate::epg::abi::NONE,
        }
    }

    /// The name of a call the guard knows, else `None`.
    pub fn syscall_name(&self, nr: u32) -> Option<&'static str> {
        use crate::epg::{nr as n, nr32 as n32};
        let name = match (self, nr) {
            (Self::X64 | Self::X32, n::READ) => "read",
            (Self::X64 | Self::X32, n::WRITE) => "write",
            (Self::X64 | Self::X32, n::IOCTL) => "ioctl",
            (Self::X64 | Self::X32, n::SETSOCKOPT) => "setsockopt",
            (Self::X64 | Self::X32, n::CLONE) => "clone",
            (Self::X64 | Self::X32, n::FORK) => "fork",
            (Self::X64 | Self::X32, n::VFORK) => "vfork",
            (Self::X64, n::EXECVE) | (Self::X32, crate::epg::X32_EXECVE) => "execve",
            (Self::X64 | Self::X32, n::SETUID) => "setuid",
            (Self::X64 | Self::X32, n::SETGID) => "setgid",
            (Self::X64 | Self::X32, n::SETREUID) => "setreuid",
            (Self::X64 | Self::X32, n::SETREGID) => "setregid",
            (Self::X64 | Self::X32, n::SETGROUPS) => "setgroups",
            (Self::X64 | Self::X32, n::SETRESUID) => "setresuid",
            (Self::X64 | Self::X32, n::SETRESGID) => "setresgid",
            (Self::X64 | Self::X32, n::SETFSUID) => "setfsuid",
            (Self::X64 | Self::X32, n::SETFSGID) => "setfsgid",
            (Self::X64 | Self::X32, n::CAPSET) => "capset",
            (Self::X64 | Self::X32, n::PIVOT_ROOT) => "pivot_root",
            (Self::X64 | Self::X32, n::PRCTL) => "prctl",
            (Self::X64 | Self::X32, n::CHROOT) => "chroot",
            (Self::X64 | Self::X32, n::KEYCTL) => "keyctl",
            (Self::X64 | Self::X32, n::UNSHARE) => "unshare",
            (Self::X64 | Self::X32, n::SETNS) => "setns",
            (Self::X64 | Self::X32, n::BPF) => "bpf",
            (Self::X64, n::EXECVEAT) | (Self::X32, crate::epg::X32_EXECVEAT) => "execveat",
            (Self::X64 | Self::X32, n::IO_URING_ENTER) => "io_uring_enter",
            (Self::X64 | Self::X32, n::CLONE3) => "clone3",
            (Self::Ia32, n32::IOCTL) => "ioctl",
            (Self::Ia32, n32::EXECVE) => "execve",
            (Self::Ia32, n32::SETUID | n32::SETUID16) => "setuid",
            (Self::Ia32, n32::SETRESUID | n32::SETRESUID16) => "setresuid",
            (Self::Ia32, n32::CAPSET) => "capset",
            (Self::Ia32, n32::UNSHARE) => "unshare",
            (Self::Ia32, n32::SETNS) => "setns",
            _ => return None,
        };
        Some(name)
    }

    /// `name(nr)` or `nr <n> (<abi>)` for the reasoning.
    pub fn describe_call(&self, nr: u32) -> String {
        if *self == Self::None || nr == crate::epg::NO_SYSCALL {
            return "no system call".to_string();
        }
        match self.syscall_name(nr) {
            Some(name) if *self == Self::X64 => format!("{name} ({nr})"),
            Some(name) => format!("{name} ({nr}, {})", self.as_str()),
            None => format!("system call {nr} ({})", self.as_str()),
        }
    }

    /// The changes this call may make legitimately (`epg::allowed`).
    pub fn allowed_changes(&self, nr: u32) -> u32 {
        crate::epg::allowed(self.wire(), nr)
    }
}

/// Lab PR 219: the credential the guard compares, as recorded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredView {
    pub uid: u32,
    pub gid: u32,
    pub suid: u32,
    pub sgid: u32,
    pub euid: u32,
    pub egid: u32,
    pub fsuid: u32,
    pub fsgid: u32,
    pub cap_permitted: u64,
    pub cap_effective: u64,
    /// `ns.inum` of the user namespace (0 when not read).
    pub user_ns: u32,
}

impl CredView {
    fn from_wire(ids: &[u32; 8], cap_permitted: u64, cap_effective: u64, user_ns: u32) -> Self {
        Self {
            uid: ids[0],
            gid: ids[1],
            suid: ids[2],
            sgid: ids[3],
            euid: ids[4],
            egid: ids[5],
            fsuid: ids[6],
            fsgid: ids[7],
            cap_permitted,
            cap_effective,
            user_ns,
        }
    }

    /// `uid=…/euid=…/suid=…/fsuid=… caps=…` for the reasoning.
    pub fn summary(&self) -> String {
        format!(
            "uid={} euid={} suid={} fsuid={} gid={} egid={} cap_eff={:#x} cap_prm={:#x} userns={}",
            self.uid,
            self.euid,
            self.suid,
            self.fsuid,
            self.gid,
            self.egid,
            self.cap_effective,
            self.cap_permitted,
            self.user_ns
        )
    }
}

impl From<&crate::wire::epg::EpgEventRaw> for Event {
    fn from(raw: &crate::wire::epg::EpgEventRaw) -> Self {
        use crate::wire::epg::flags as f;
        Event::ExploitPostcondition {
            kind: EpgKind::from_wire(raw.kind),
            killed: raw.action == crate::epg::action::KILLED,
            kill_failed: raw.action == crate::epg::action::KILL_FAILED,
            pid: raw.pid,
            tid: raw.tid,
            uid: raw.before_ids[0],
            comm: crate::wire::cstr_lossy(&raw.comm).into_owned(),
            abi: SyscallAbi::from_wire(raw.abi),
            syscall: raw.nr,
            mechanisms: raw.mechanisms,
            before: CredView::from_wire(
                &raw.before_ids,
                raw.before_cap_permitted,
                raw.before_cap_effective,
                raw.before_user_ns,
            ),
            after: CredView::from_wire(
                &raw.after_ids,
                raw.after_cap_permitted,
                raw.after_cap_effective,
                raw.after_user_ns,
            ),
            mnt_ns: (raw.before_mnt_ns, raw.after_mnt_ns),
            pid_ns: (raw.before_pid_ns, raw.after_pid_ns),
            net_ns: (raw.before_net_ns, raw.after_net_ns),
            cred_replaced: raw.flags & f::CRED_REPLACED != 0,
            root_changed: raw.flags & f::ROOT_CHANGED != 0,
            fs_changed: raw.flags & f::FS_CHANGED != 0,
            exit_bypassed: raw.flags & f::EXIT_BYPASSED != 0,
            timestamp_ns: raw.timestamp_ns,
            injected: raw.flags & f::INJECTED != 0,
            variant: GuardVariant::from_wire(raw.variant),
            caught_at: CatchPoint::from_wire(raw.point),
            baseline_lost: raw.flags & f::BASELINE_LOST != 0,
            rebaselined: raw.flags & f::REBASELINED != 0,
        }
    }
}

/// External audit EBPF-013: the sensor whose kernel record budget held
/// records back ([`Event::SensorFlood`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FloodSource {
    /// `inet_csk_listen_start` (TCP `listen()`).
    Listen,
    /// `io_uring_create` (`io_uring_setup()`).
    IoUringCreate,
}

impl FloodSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Listen => "listen",
            Self::IoUringCreate => "io_uring_create",
        }
    }
}

/// External audit EBPF-013: the [`Event::SensorFlood`]s a record carries —
/// one for the process's held count, one for its user's, each only when
/// nonzero.
pub fn sensor_floods(
    source: FloodSource,
    pid: u32,
    uid: u32,
    comm: &str,
    held: u32,
    held_uid: u32,
    timestamp_ns: u64,
) -> [Option<Event>; 2] {
    let flood = |held: u32, uid_level: bool| {
        (held != 0).then(|| Event::SensorFlood {
            source,
            pid,
            uid,
            comm: comm.to_string(),
            exe: None,
            held,
            uid_level,
            timestamp_ns,
        })
    };
    [flood(held, false), flood(held_uid, true)]
}

/// External audit EBPF-013: the floods an io_uring record carries (CREATE
/// records only; ACTIVITY records are aggregated, not budgeted).
pub fn io_uring_floods(raw: &crate::wire::IoUringRaw) -> [Option<Event>; 2] {
    if raw.kind != crate::wire::IOURING_KIND_CREATE {
        return [None, None];
    }
    sensor_floods(
        FloodSource::IoUringCreate,
        raw.pid,
        raw.uid,
        &crate::wire::cstr_lossy(&raw.comm),
        raw.held,
        raw.held_uid,
        raw.timestamp_ns,
    )
}

/// Std-side mirror of [`crate::wire::admin_signed_payload::
/// CanaryTypeWire`] for `Event::CanaryTripped`. Same 4
/// variants in the same order; identical serde wire bytes.
/// Distinct type so the std-only `Event` enum doesn't pull in
/// the wire-protocol `SignedPayloadError` dependency tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanaryTypeTag {
    File,
    Process,
    Network,
    Credential,
}

/// What kind of access tripped a canary. Drives K3 detector
/// dispatch + K5 rule reasoning text. Mirrors design §4.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanaryAccessKind {
    /// File or credential canary — `inode_file_open` LSM hook
    /// fired on the watched inode (the K3 detector intercepts
    /// the `Event::Fim` emit BEFORE the rule layer sees it
    /// per §12 Q9 inline-filter lock-in).
    FileOpen,
    /// Process canary — `sched_process_exec` tracepoint fired
    /// on the canary binary's path.
    ProcessExec,
    /// Network listener canary — the agent's own
    /// `TcpListener::accept()` returned (immediate-close per
    /// §12 Q6 lock-in; the connect itself is the signal).
    NetworkConnect,
}

/// Which inode operation the LSM hook denied. Wire-side these are
/// the `FS_OP_*` byte constants in [`crate::wire`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FsProtectOperation {
    /// `unlink(2)` — `rm` of a file inside or pointing at the
    /// protected set.
    Unlink,
    /// `rmdir(2)` — removal of a protected directory.
    Rmdir,
    /// `rename(2)` / `renameat2(2)` involving a protected inode on
    /// either side.
    Rename,
    /// `chmod` / `chown` / `truncate` via `notify_change`.
    Setattr,
    /// `ioctl(FS_IOC_SETFLAGS, ...)` — the `chattr -i` defense.
    Ioctl,
    /// at-authz-1: a write-intent `open(2)` of a WRITE-protected inode —
    /// the `file_open` deny that closes the `tee -a admin.pub` /
    /// in-place-`pwrite` gap.
    Write,
    /// Write handle on one of the agent's own BPF maps (BPF self-defence).
    BpfMap,
    /// A handle to one of the agent's own BPF links (by id or by pin)
    /// refused to a foreign process: the shape of `bpftool link detach`.
    BpfLink,
    /// A signal to a protected pid refused by the `task_kill` hook.
    Signal,
    /// A ptrace ATTACH-mode access to a protected pid refused.
    Ptrace,
    /// A kexec kernel image load refused (review 82).
    Kexec,
    /// External audit EVD-001: an open of the agent's private signing key
    /// by a process outside its family, a read included.
    Read,
    /// External audit EBPF-015: a new entry in one of the agent's
    /// directories (`open(O_CREAT)`, `creat`, a bpffs pin); the target is
    /// the directory.
    Create,
    /// A hard link made in one of the agent's directories.
    Link,
    /// A symlink made in one of the agent's directories.
    Symlink,
    /// A subdirectory made in one of the agent's directories.
    Mkdir,
    /// A device node, FIFO or socket made in one of the agent's
    /// directories.
    Mknod,
    /// An extended attribute (or, on 6.2+, a POSIX ACL) set or removed on
    /// a protected inode; `security.selinux` is not refused.
    Xattr,
    /// Wire byte the agent does not recognise (forward-compatible
    /// safety net).
    Unknown(u8),
}

impl FsProtectOperation {
    pub fn from_wire(byte: u8) -> Self {
        match byte {
            FS_OP_UNLINK => Self::Unlink,
            FS_OP_RMDIR => Self::Rmdir,
            FS_OP_RENAME => Self::Rename,
            FS_OP_SETATTR => Self::Setattr,
            FS_OP_IOCTL => Self::Ioctl,
            FS_OP_WRITE => Self::Write,
            FS_OP_BPF_MAP => Self::BpfMap,
            FS_OP_BPF_LINK => Self::BpfLink,
            FS_OP_SIGNAL => Self::Signal,
            FS_OP_PTRACE => Self::Ptrace,
            FS_OP_KEXEC => Self::Kexec,
            FS_OP_READ => Self::Read,
            FS_OP_CREATE => Self::Create,
            FS_OP_LINK => Self::Link,
            FS_OP_SYMLINK => Self::Symlink,
            FS_OP_MKDIR => Self::Mkdir,
            FS_OP_MKNOD => Self::Mknod,
            FS_OP_XATTR => Self::Xattr,
            other => Self::Unknown(other),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unlink => "unlink",
            Self::Rmdir => "rmdir",
            Self::Rename => "rename",
            Self::Setattr => "setattr",
            Self::Ioctl => "ioctl",
            Self::BpfMap => "bpf_map",
            Self::BpfLink => "bpf_link",
            Self::Signal => "signal",
            Self::Ptrace => "ptrace",
            Self::Kexec => "kexec",
            Self::Write => "write",
            Self::Read => "read",
            Self::Create => "create",
            Self::Link => "link",
            Self::Symlink => "symlink",
            Self::Mkdir => "mkdir",
            Self::Mknod => "mknod",
            Self::Xattr => "xattr",
            Self::Unknown(_) => "unknown",
        }
    }
}

impl core::fmt::Display for FsProtectOperation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unknown(b) => write!(f, "unknown({b})"),
            other => f.write_str(other.as_str()),
        }
    }
}

/// Decode the NUL-separated argv blob (Tappa 10.6 §13 Q1) into argument
/// strings. `len` is the kernel-reported byte count (`argv_len`, clamped
/// to the buffer). Trailing/empty segments (from a trailing NUL or a
/// zero-padded tail) are dropped; each arg is UTF-8 lossy-decoded. A
/// zeroed blob (older BPF / mixed fleet) yields an empty `Vec`.
pub fn parse_argv_blob(blob: &[u8], len: u16) -> Vec<String> {
    let end = core::cmp::min(len as usize, blob.len());
    blob[..end]
        .split(|&b| b == 0)
        .filter(|seg| !seg.is_empty())
        .map(|seg| String::from_utf8_lossy(seg).into_owned())
        .collect()
}

impl From<&ProcessSpawnRaw> for Event {
    fn from(raw: &ProcessSpawnRaw) -> Self {
        Event::ProcessSpawn {
            pid: raw.pid,
            ppid: raw.ppid,
            uid: raw.uid,
            gid: raw.gid,
            comm: crate::wire::cstr_lossy(&raw.comm).into_owned(),
            filename: crate::wire::cstr_lossy(&raw.filename).into_owned(),
            timestamp_ns: raw.timestamp_ns,
            argv: parse_argv_blob(&raw.argv, raw.argv_len),
            parent_comm: crate::wire::cstr_lossy(&raw.parent_comm).into_owned(),
            parent_start_ns: raw.parent_start_ns,
            start_ns: raw.start_ns,
            // Cluster 15.3 / R011: any non-zero byte from the BPF side
            // is "parent IS a kthread". Zero (the default for a BPF
            // read failure OR an older BPF that doesn't set this
            // field) decodes to `false` → R011 fail-secure path.
            parent_is_kthread: raw.parent_is_kthread != 0,
            exe: ExeIdentity::from_raw(&raw.exe),
            argv_truncated: raw.trunc_flags & crate::wire::spawn_trunc::ARGV != 0,
            filename_truncated: raw.trunc_flags & crate::wire::spawn_trunc::FILENAME != 0,
            stdio: StdioSockets {
                own: StdioSocket::from_raw(&raw.stdio),
                parent: StdioSocket::from_raw(&raw.parent_stdio),
            },
        }
    }
}

impl From<&FileOpenRaw> for Event {
    fn from(raw: &FileOpenRaw) -> Self {
        Event::FileOpen {
            pid: raw.pid,
            uid: raw.uid,
            gid: raw.gid,
            comm: crate::wire::cstr_lossy(&raw.comm).into_owned(),
            filename: crate::wire::cstr_lossy(&raw.filename).into_owned(),
            flags: raw.flags,
            timestamp_ns: raw.timestamp_ns,
            path_from_user: true,
            kernel_class: 0,
        }
    }
}

impl From<&ExecCheckRaw> for Event {
    fn from(raw: &ExecCheckRaw) -> Self {
        Event::ExecCheck {
            pid: raw.pid,
            ppid: raw.ppid,
            uid: raw.uid,
            comm: crate::wire::cstr_lossy(&raw.comm).into_owned(),
            filename: crate::wire::cstr_lossy(&raw.filename).into_owned(),
            timestamp_ns: raw.timestamp_ns,
            exe: ExeIdentity::from_raw(&raw.exe),
        }
    }
}

/// Lab PR 224 (CM-03): the standard streams of an exec's process and of
/// its parent ([`Event::ProcessSpawn::stdio`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StdioSockets {
    #[serde(default)]
    pub own: StdioSocket,
    #[serde(default)]
    pub parent: StdioSocket,
}

/// Lab PR 224 (CM-03): one task's fds 0..2 at an exec, decoded from
/// [`crate::wire::StdioRaw`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StdioSocket {
    /// The kernel read the task's file table: the fields below say what
    /// is there. `false`: unknown (an offset missing on this kernel, an
    /// older eBPF object), never "no socket".
    #[serde(default)]
    pub read: bool,
    /// Bit `n` set: fd `n` (0 stdin, 1 stdout, 2 stderr) is an
    /// `AF_INET` / `AF_INET6` socket.
    #[serde(default)]
    pub inet_fds: u8,
    /// One of those sockets was connected out by a local process (the
    /// connect kprobe recorded it).
    #[serde(default)]
    pub outbound: bool,
    /// `sk_protocol` of the first one (6 TCP, 17 UDP), 0 when unknown.
    #[serde(default)]
    pub proto: u8,
    /// The first one's peer, when it has one.
    #[serde(default)]
    pub peer: Option<std::net::SocketAddr>,
}

impl StdioSocket {
    pub fn from_raw(raw: &crate::wire::StdioRaw) -> Self {
        use crate::wire::stdio_flags;
        if raw.flags & stdio_flags::READ == 0 {
            return Self::default();
        }
        let inet_fds = (raw.flags & stdio_flags::ANY_INET) >> 1;
        let peer =
            (inet_fds != 0 && raw.peer_port != 0 && matches!(raw.family, 2 | 10)).then(|| {
                std::net::SocketAddr::new(
                    crate::netaddr::canonical_ip(raw.family, &raw.peer_addr),
                    raw.peer_port,
                )
            });
        Self {
            read: true,
            inet_fds,
            outbound: inet_fds != 0 && raw.flags & stdio_flags::OUTBOUND != 0,
            proto: raw.proto,
            peer,
        }
    }

    /// stdin or stdout is an inet socket: the shell's input or output
    /// is the network.
    pub fn stdin_or_stdout_inet(&self) -> bool {
        self.read && self.inet_fds & 0b011 != 0
    }

    /// `tcp`, `udp`, or `inet` when the protocol is unknown.
    pub fn proto_name(&self) -> &'static str {
        match self.proto {
            6 => "tcp",
            17 => "udp",
            _ => "inet",
        }
    }
}

/// Tappa 10.9 step 2: what the kernel executed (`wire::exe`), decoded.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExeIdentity {
    /// Canonical path of the executed file, rebuilt from its dentry:
    /// the exec'ing task's own view, or absolute once userland mapped the
    /// filesystem root to its mount point. Empty when unknown.
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub dev: u64,
    #[serde(default)]
    pub ino: u64,
    /// `wire::exe::exe_flags`.
    #[serde(default)]
    pub flags: u32,
    /// binfmt pass: 0 = the file the caller named, 1+ = interpreters.
    #[serde(default)]
    pub pass: u8,
    /// Filesystem root `path` is relative to, until userland maps it to
    /// a mount point; `(0, 0)` once `path` is the task's view or absolute.
    #[serde(skip)]
    pub root: (u64, u64),
}

impl ExeIdentity {
    pub fn from_raw(raw: &crate::wire::exe::ExeIdentityRaw) -> Self {
        use crate::wire::exe::exe_flags;
        let path = crate::wire::exe::relative_path(raw);
        let root = if path.is_empty() || raw.flags & exe_flags::TASK_ROOT != 0 {
            (0, 0)
        } else {
            (raw.root_dev, raw.root_ino)
        };
        ExeIdentity {
            path,
            dev: raw.dev,
            ino: raw.ino,
            flags: raw.flags,
            pass: raw.pass,
            root,
        }
    }

    /// The canonical path, or `fallback` (the caller's string) when it is
    /// unknown or not yet mapped to a mount point.
    pub fn path_or<'a>(&'a self, fallback: &'a str) -> &'a str {
        if self.path.is_empty() || self.root != (0, 0) {
            fallback
        } else {
            &self.path
        }
    }

    pub fn has(&self, flag: u32) -> bool {
        self.flags & flag != 0
    }
}

/// How a kernel module was loaded (BUG-034). Decoded from
/// [`crate::wire::ModuleLoadRaw::method`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ModuleLoadMethod {
    /// `finit_module(2)` via the `kernel_read_file` LSM hook — carries a source path.
    Finit,
    /// `init_module(2)` via the `kernel_load_data` LSM hook — legacy buffer, no path.
    Init,
    /// Unrecognised method byte (forward-compat).
    Unknown,
}

impl From<&crate::wire::BpfSyscallRaw> for Event {
    fn from(raw: &crate::wire::BpfSyscallRaw) -> Self {
        Event::BpfSyscall {
            pid: raw.pid,
            uid: raw.uid,
            comm: crate::wire::cstr_lossy(&raw.comm).into_owned(),
            cmd: raw.cmd,
            arg: raw.arg,
            timestamp_ns: raw.timestamp_ns,
        }
    }
}

impl From<&crate::wire::IoUringRaw> for Event {
    fn from(raw: &crate::wire::IoUringRaw) -> Self {
        Event::IoUring {
            created: raw.kind == crate::wire::IOURING_KIND_CREATE,
            pid: raw.pid,
            uid: raw.uid,
            comm: crate::wire::cstr_lossy(&raw.comm).into_owned(),
            classes: raw.classes,
            count: raw.count,
            last_opcode: raw.last_opcode,
            sq_thread: raw.sq_thread != 0,
            timestamp_ns: raw.timestamp_ns,
        }
    }
}

/// Human names of the classes set in an `IoUring` bitmap, in bit order.
pub fn io_uring_class_names(classes: u32) -> alloc::vec::Vec<&'static str> {
    let table = [
        (crate::wire::IOURING_CLASS_FILE_OPEN, "file_open"),
        (crate::wire::IOURING_CLASS_FILE_RW, "file_rw"),
        (crate::wire::IOURING_CLASS_NET_CONNECT, "net_connect"),
        (crate::wire::IOURING_CLASS_NET_SENDRECV, "net_sendrecv"),
        (crate::wire::IOURING_CLASS_FS_MUTATE, "fs_mutate"),
        (crate::wire::IOURING_CLASS_OTHER, "other"),
    ];
    table
        .iter()
        .filter(|(bit, _)| classes & bit != 0)
        .map(|(_, n)| *n)
        .collect()
}

impl From<&crate::wire::ModuleLoadRaw> for Event {
    fn from(raw: &crate::wire::ModuleLoadRaw) -> Self {
        let method = match raw.method {
            crate::wire::MODULE_LOAD_FINIT => ModuleLoadMethod::Finit,
            crate::wire::MODULE_LOAD_INIT => ModuleLoadMethod::Init,
            _ => ModuleLoadMethod::Unknown,
        };
        Event::ModuleLoad {
            method,
            loader_pid: raw.loader_pid,
            loader_uid: raw.loader_uid,
            loader_comm: crate::wire::cstr_lossy(&raw.loader_comm).into_owned(),
            parent_comm: crate::wire::cstr_lossy(&raw.parent_comm).into_owned(),
            parent_is_kthread: raw.parent_is_kthread != 0,
            path: reconstruct_module_path(&raw.path, raw.path_len as usize, raw.path_truncated),
            timestamp_ns: raw.timestamp_ns,
        }
    }
}

/// Reverse the leaf→root component slots the `kernel_read_file` hook
/// wrote (each in a fixed 32-byte slot of [`crate::wire::ModuleLoadRaw::path`])
/// into a forward path. `slots` = `path_len` (component count).
/// Returns `None` when nothing resolved (init_module, or a failed walk).
/// `truncated` (wire `path_truncated`) means the kernel walk ran out of
/// slots before the filesystem root: the result is then RELATIVE (no
/// leading `/`) so a consumer can tell "prefix unknown" from a real
/// absolute path. Audit `abi-modpath-1`: the old code always prepended
/// `/`, turning `…/<ver>/kernel/…/e1000e.ko.zst` into a bogus
/// non-standard absolute path that R018 killed on.
fn reconstruct_module_path(
    path: &[u8; crate::wire::MODULE_PATH_LEN],
    slots: usize,
    truncated: u8,
) -> Option<String> {
    const SLOT: usize = 32;
    let n = slots.min(crate::wire::MODULE_PATH_LEN / SLOT);
    let mut comps: Vec<String> = Vec::with_capacity(n);
    for i in 0..n {
        let s = &path[i * SLOT..i * SLOT + SLOT];
        let end = s.iter().position(|&b| b == 0).unwrap_or(SLOT);
        if end == 0 {
            continue;
        }
        // External audit PROC-005: a component that is not UTF-8 was
        // dropped, and `<bytes>/lib/modules/…` collapsed into a standard
        // path. It is kept, lossily, and the path is no module directory.
        comps.push(String::from_utf8_lossy(&s[..end]).into_owned());
    }
    if comps.is_empty() {
        return None;
    }
    comps.reverse(); // kernel wrote leaf→root; flip to root→leaf
    let joined = comps.join("/");
    if truncated != 0 {
        // Prefix unknown: keep it relative, strip any stray leading '/'.
        // External audit PROC-004: a path deeper than the walk's slots
        // reads "…/<components>" — see `module_path_too_deep`.
        let rel = joined.trim_start_matches('/');
        return Some(if truncated == crate::wire::MODULE_PATH_TOO_DEEP {
            format!("{MODULE_PATH_DEEPER}{rel}")
        } else {
            rel.to_string()
        });
    }
    Some(if joined.starts_with("//") {
        joined[1..].to_string()
    } else if joined.starts_with('/') {
        joined
    } else {
        format!("/{joined}")
    })
}

/// `true` when a [`Event::ModuleLoad`] path came back truncated (see
/// [`reconstruct_module_path`]): relative, i.e. no leading `/`.
pub fn module_path_is_truncated(path: &str) -> bool {
    !path.starts_with('/')
}

/// What a module path deeper than the kernel walk's slots starts with:
/// "there is more above".
const MODULE_PATH_DEEPER: &str = "…/";

/// External audit PROC-004: `true` when a truncated module path is so only
/// because it is deeper than the walk's slots (16 components) — deeper
/// than any module directory, so not a legitimate location, whatever lies
/// above. `false` for a complete path, and for one a failed read left
/// unknown.
pub fn module_path_too_deep(path: &str) -> bool {
    path.starts_with(MODULE_PATH_DEEPER)
}

impl From<&TcpConnectRaw> for Event {
    fn from(raw: &TcpConnectRaw) -> Self {
        Event::TcpConnect {
            pid: raw.pid,
            uid: raw.uid,
            comm: crate::wire::cstr_lossy(&raw.comm).into_owned(),
            family: raw.family,
            src_addr: raw.src_addr,
            src_port: raw.src_port,
            dst_addr: raw.dst_addr,
            dst_port: raw.dst_port,
            timestamp_ns: raw.timestamp_ns,
        }
    }
}

impl From<&FsProtectDenialRaw> for Event {
    fn from(raw: &FsProtectDenialRaw) -> Self {
        Event::FsProtectDenial {
            pid: raw.attacker_pid,
            uid: raw.attacker_uid,
            comm: crate::wire::cstr_lossy(&raw.attacker_comm).into_owned(),
            target_dev: raw.target_dev,
            target_ino: raw.target_ino,
            operation: FsProtectOperation::from_wire(raw.operation),
            timestamp_ns: raw.timestamp_ns,
        }
    }
}

impl From<&DnsQueryRaw> for Event {
    fn from(raw: &DnsQueryRaw) -> Self {
        let len = (raw.qname_len as usize).min(raw.query_name.len());
        let bytes = &raw.query_name[..len];
        let query_name = decode_dns_qname(bytes);
        // Tappa 10.9 step 3: the socket-buffer sensor copies wire bytes from
        // the start of the name; its end, and the type after it, are found
        // here (a zero byte inside a label does not end the name). The
        // `udp_sendmsg` sensor fills `qtype` in the kernel.
        let (query_type, qname_partial) = if raw.flags & crate::wire::dns_flags::SKB != 0 {
            match qname_wire_end(bytes) {
                Some(end) => (
                    bytes
                        .get(end..end + 2)
                        .map_or(0, |t| u16::from_be_bytes([t[0], t[1]])),
                    false,
                ),
                None => (0, true),
            }
        } else {
            (raw.qtype, false)
        };
        Event::DnsQuery {
            pid: raw.pid,
            uid: raw.uid,
            comm: crate::wire::cstr_lossy(&raw.comm).into_owned(),
            // FP-3: the sender exe is NOT carried on the wire (the BPF
            // event has no room for a path); userland resolves it
            // best-effort in `pump_dns_query` right after this `From`.
            exe: None,
            query_name,
            query_type,
            dns_server: raw.dns_server,
            family: raw.family,
            timestamp_ns: raw.timestamp_ns,
            qname_partial,
        }
    }
}

/// Severity assigned to a verdict.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Action the response layer should take in reaction to a verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ResponseAction {
    Log,
    KillProcess,
    KillProcessTree,
    BlockOutbound,
    FullNetworkIsolation,
    Quarantine,
    ThrottleProcess,
    /// Review 86: remove the `security.capability` xattr from the
    /// verdict's file, undoing a capability grant. Acts on the file, not
    /// on the process.
    StripFileCapability,
}

/// Decision produced by the engine for a given event.
///
/// `rule_id` is the stable identifier (e.g. `"R001_ExecFromTmp"`) used
/// for telemetry and correlation; `event_pid` / `event_filename` /
/// `timestamp_ns` snapshot the relevant pieces of the triggering
/// event so a verdict can be logged or routed without keeping the
/// original `Event` around.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verdict {
    pub rule_id: String,
    pub rule_name: String,
    pub category: String,
    pub action: ResponseAction,
    pub severity: Severity,
    pub reasoning: String,
    pub event_pid: u32,
    pub event_filename: String,
    pub timestamp_ns: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// External audit EBPF-015: the six denial codes of the new-entry and
    /// extended-attribute hooks decode to their own operation (not
    /// `Unknown`), with the names the journal line and the tamper check
    /// print.
    #[test]
    fn fs_protect_new_entry_and_xattr_ops_decode() {
        use crate::wire::{
            FS_OP_CREATE, FS_OP_LINK, FS_OP_MKDIR, FS_OP_MKNOD, FS_OP_SYMLINK, FS_OP_XATTR,
        };
        let cases = [
            (FS_OP_CREATE, FsProtectOperation::Create, "create"),
            (FS_OP_LINK, FsProtectOperation::Link, "link"),
            (FS_OP_SYMLINK, FsProtectOperation::Symlink, "symlink"),
            (FS_OP_MKDIR, FsProtectOperation::Mkdir, "mkdir"),
            (FS_OP_MKNOD, FsProtectOperation::Mknod, "mknod"),
            (FS_OP_XATTR, FsProtectOperation::Xattr, "xattr"),
        ];
        for (byte, op, name) in cases {
            assert_eq!(FsProtectOperation::from_wire(byte), op);
            assert_eq!(op.as_str(), name);
            assert_eq!(op.to_string(), name);
        }
        let mut raw = FsProtectDenialRaw::zeroed();
        raw.operation = FS_OP_MKDIR;
        raw.target_ino = 42;
        match Event::from(&raw) {
            Event::FsProtectDenial {
                operation,
                target_ino,
                ..
            } => {
                assert_eq!(operation, FsProtectOperation::Mkdir);
                assert_eq!(target_ino, 42);
            }
            other => panic!("{other:?}"),
        }
    }
    use crate::wire::{ProcessSpawnRaw, FILENAME_LEN, QNAME_LEN, TASK_COMM_LEN};

    #[test]
    fn file_open_raw_to_event() {
        let mut raw = FileOpenRaw::zeroed();
        raw.pid = 42;
        raw.uid = 1000;
        raw.gid = 1000;
        raw.flags = 0o2; // O_RDWR
        raw.comm[..3].copy_from_slice(b"cat");
        raw.filename[..11].copy_from_slice(b"/etc/passwd");
        raw.timestamp_ns = 7;
        match Event::from(&raw) {
            Event::FileOpen {
                pid,
                comm,
                filename,
                flags,
                ..
            } => {
                assert_eq!(pid, 42);
                assert_eq!(comm, "cat");
                assert_eq!(filename, "/etc/passwd");
                assert_eq!(flags, 0o2);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn tcp_connect_raw_to_event_carries_addresses_and_ports() {
        let mut raw = TcpConnectRaw::zeroed();
        raw.pid = 11;
        raw.family = 2; // AF_INET
        raw.src_addr[..4].copy_from_slice(&[10, 0, 0, 5]);
        raw.dst_addr[..4].copy_from_slice(&[8, 8, 8, 8]);
        raw.src_port = 54321;
        raw.dst_port = 53;
        raw.comm[..4].copy_from_slice(b"curl");
        match Event::from(&raw) {
            Event::TcpConnect {
                family,
                src_addr,
                dst_addr,
                src_port,
                dst_port,
                comm,
                ..
            } => {
                assert_eq!(family, 2);
                assert_eq!(&src_addr[..4], &[10, 0, 0, 5]);
                assert_eq!(&dst_addr[..4], &[8, 8, 8, 8]);
                assert_eq!(src_port, 54321);
                assert_eq!(dst_port, 53);
                assert_eq!(comm, "curl");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn dns_query_raw_to_event_decodes_qname() {
        let mut raw = DnsQueryRaw::zeroed();
        raw.pid = 99;
        raw.qtype = 1;
        let qname = b"\x07example\x03com\x00";
        raw.qname_len = qname.len() as u16;
        raw.query_name[..qname.len()].copy_from_slice(qname);
        match Event::from(&raw) {
            Event::DnsQuery {
                query_name,
                query_type,
                ..
            } => {
                assert_eq!(query_name, "example.com");
                assert_eq!(query_type, 1);
            }
            _ => panic!("wrong variant"),
        }
        // Sanity: the size constant is honoured.
        assert_eq!(QNAME_LEN, 253);
    }

    /// A record from the socket-buffer sensor (Tappa 10.9 step 3): wire
    /// bytes from the start of the name; the type comes after the root label.
    fn skb_raw(wire: &[u8]) -> DnsQueryRaw {
        let mut raw = DnsQueryRaw::zeroed();
        raw.flags = crate::wire::dns_flags::SKB;
        raw.qtype = 0xffff; // ignored in this mode
        raw.qname_len = wire.len() as u16;
        raw.query_name[..wire.len()].copy_from_slice(wire);
        raw
    }

    fn dns_fields(ev: Event) -> (String, u16, bool) {
        match ev {
            Event::DnsQuery {
                query_name,
                query_type,
                qname_partial,
                ..
            } => (query_name, query_type, qname_partial),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn skb_record_takes_the_type_after_the_root_label() {
        // example.com, TXT (16), class IN
        let raw = skb_raw(b"\x07example\x03com\x00\x00\x10\x00\x01");
        assert_eq!(
            dns_fields(Event::from(&raw)),
            ("example.com".into(), 16, false)
        );
    }

    /// The `udp_sendmsg` sensor stopped at the first zero byte, so a zero
    /// inside a label cut the name; the label walk does not.
    #[test]
    fn skb_record_keeps_a_label_with_a_zero_byte() {
        let raw = skb_raw(b"\x05ab\x00cd\x04evil\x00\x00\x01\x00\x01");
        assert_eq!(
            dns_fields(Event::from(&raw)),
            // External audit NN-AUD-185: `\000`, not a `?` shared by every
            // unprintable byte
            ("ab\\000cd.evil".into(), 1, false)
        );
    }

    /// The name runs past the bytes read (a corked send: the rest is in a
    /// page fragment): partial, no type.
    #[test]
    fn skb_record_without_a_root_label_is_partial() {
        let raw = skb_raw(b"\x10aaaaaaaaaaaaaaaa\x06bbb");
        let (name, qtype, partial) = dns_fields(Event::from(&raw));
        assert_eq!(name, "aaaaaaaaaaaaaaaa.bbb");
        assert_eq!((qtype, partial), (0, true));
        // Nothing read at all is partial too.
        assert!(dns_fields(Event::from(&skb_raw(b""))).2);
        // A compression pointer in a query's own name.
        assert!(dns_fields(Event::from(&skb_raw(b"\x03abc\xc0\x0c"))).2);
    }

    #[test]
    fn sendmsg_record_keeps_the_kernel_type() {
        let mut raw = DnsQueryRaw::zeroed();
        raw.qtype = 28;
        let qname = b"\x04host\x00";
        raw.qname_len = 5; // the string read does not count the root label
        raw.query_name[..qname.len()].copy_from_slice(qname);
        assert_eq!(dns_fields(Event::from(&raw)), ("host".into(), 28, false));
    }

    #[test]
    fn process_spawn_raw_to_event_is_lossy_safe() {
        let mut raw = ProcessSpawnRaw::zeroed();
        raw.pid = 4242;
        raw.ppid = 1;
        raw.uid = 1000;
        raw.gid = 1000;
        raw.timestamp_ns = 123_456_789;
        raw.comm[..2].copy_from_slice(b"ls");
        raw.filename[..7].copy_from_slice(b"/bin/ls");

        let evt: Event = (&raw).into();
        match evt {
            Event::ProcessSpawn {
                pid,
                ppid,
                uid,
                gid,
                comm,
                filename,
                timestamp_ns,
                ..
            } => {
                assert_eq!(pid, 4242);
                assert_eq!(ppid, 1);
                assert_eq!(uid, 1000);
                assert_eq!(gid, 1000);
                assert_eq!(comm, "ls");
                assert_eq!(filename, "/bin/ls");
                assert_eq!(timestamp_ns, 123_456_789);
            }
            _ => panic!("expected ProcessSpawn"),
        }
        // Sanity: the consts we rely on did not silently drift.
        assert_eq!(TASK_COMM_LEN, 16);
        assert_eq!(FILENAME_LEN, 256);
    }

    // ── Tappa 10.6 D1 — argv blob + parent context ──────────────────

    #[test]
    fn parse_argv_blob_empty_is_empty_vec() {
        assert!(parse_argv_blob(&[0u8; crate::wire::ARGV_LEN], 0).is_empty());
        // A fully-zeroed blob with a stray len still yields nothing.
        assert!(parse_argv_blob(&[0u8; crate::wire::ARGV_LEN], 10).is_empty());
    }

    #[test]
    fn parse_argv_blob_single_arg() {
        let mut b = [0u8; crate::wire::ARGV_LEN];
        b[..3].copy_from_slice(b"ls\0");
        assert_eq!(parse_argv_blob(&b, 3), vec!["ls".to_string()]);
    }

    #[test]
    fn parse_argv_blob_multiple_args() {
        let mut b = [0u8; crate::wire::ARGV_LEN];
        let blob = b"bash\0-c\0id; whoami\0";
        b[..blob.len()].copy_from_slice(blob);
        assert_eq!(
            parse_argv_blob(&b, blob.len() as u16),
            vec![
                "bash".to_string(),
                "-c".to_string(),
                "id; whoami".to_string()
            ]
        );
    }

    #[test]
    fn parse_argv_blob_truncated_non_nul_terminated() {
        // Kernel hit the cap mid-arg: last segment has no trailing NUL.
        let mut b = [0u8; crate::wire::ARGV_LEN];
        let blob = b"curl\0http://very-long";
        b[..blob.len()].copy_from_slice(blob);
        // `argv_len` clamps the slice; the dangling segment is still
        // returned (best-effort), no panic.
        assert_eq!(
            parse_argv_blob(&b, blob.len() as u16),
            vec!["curl".to_string(), "http://very-long".to_string()]
        );
    }

    #[test]
    fn parse_argv_blob_invalid_utf8_is_lossy() {
        let mut b = [0u8; crate::wire::ARGV_LEN];
        // "a" + invalid byte 0xFF + NUL.
        b[0] = b'a';
        b[1] = 0xFF;
        b[2] = 0;
        let out = parse_argv_blob(&b, 3);
        assert_eq!(out.len(), 1);
        assert!(out[0].starts_with('a'));
        assert!(out[0].contains('\u{FFFD}')); // lossy replacement char
    }

    #[test]
    fn parse_argv_blob_len_clamped_to_buffer() {
        // A bogus len larger than the buffer must not panic.
        let mut b = [0u8; crate::wire::ARGV_LEN];
        b[..3].copy_from_slice(b"ls\0");
        assert_eq!(parse_argv_blob(&b, u16::MAX), vec!["ls".to_string()]);
    }

    #[test]
    fn process_spawn_event_roundtrips_with_new_fields() {
        let mut raw = ProcessSpawnRaw::zeroed();
        raw.pid = 100;
        raw.ppid = 50;
        raw.timestamp_ns = 7;
        raw.comm[..4].copy_from_slice(b"curl");
        raw.parent_comm[..4].copy_from_slice(b"bash");
        raw.parent_start_ns = 999;
        let blob = b"curl\0-s\0http://x\0";
        raw.argv[..blob.len()].copy_from_slice(blob);
        raw.argv_len = blob.len() as u16;

        let evt: Event = (&raw).into();
        let json = serde_json::to_string(&evt).unwrap();
        let back: Event = serde_json::from_str(&json).unwrap();
        match back {
            Event::ProcessSpawn {
                argv,
                parent_comm,
                parent_start_ns,
                ppid,
                ..
            } => {
                assert_eq!(argv, vec!["curl", "-s", "http://x"]);
                assert_eq!(parent_comm, "bash");
                assert_eq!(parent_start_ns, 999);
                assert_eq!(ppid, 50);
            }
            _ => panic!("expected ProcessSpawn"),
        }
    }

    #[test]
    fn process_spawn_event_deserializes_old_record_via_serde_default() {
        // Mixed-fleet: an older agent's serialized record has none of the
        // T10.6 fields. `#[serde(default)]` must fill them gracefully.
        let old = r#"{"ProcessSpawn":{
            "pid":1,"ppid":0,"uid":0,"gid":0,
            "comm":"sh","filename":"/bin/sh","timestamp_ns":42}}"#;
        let evt: Event = serde_json::from_str(old).unwrap();
        match evt {
            Event::ProcessSpawn {
                argv,
                parent_comm,
                parent_start_ns,
                argv_truncated,
                filename_truncated,
                ..
            } => {
                assert!(argv.is_empty());
                assert_eq!(parent_comm, "");
                assert_eq!(parent_start_ns, 0);
                // External audit EBPF-021: an older record is "not known
                // to be cut".
                assert!(!argv_truncated);
                assert!(!filename_truncated);
            }
            _ => panic!("expected ProcessSpawn"),
        }
    }

    /// External audit EBPF-021: the kernel's cut marks reach the event and
    /// survive a round trip; a record without them reads as whole.
    #[test]
    fn trunc_flags_decode() {
        use crate::wire::spawn_trunc;
        let decode = |flags: u8| {
            let mut raw = ProcessSpawnRaw::zeroed();
            raw.comm[..5].copy_from_slice(b"socat");
            let blob = b"socat\0-d\0-d\0";
            raw.argv[..blob.len()].copy_from_slice(blob);
            raw.argv_len = blob.len() as u16;
            raw.trunc_flags = flags;
            let evt: Event = (&raw).into();
            let back: Event = serde_json::from_str(&serde_json::to_string(&evt).unwrap()).unwrap();
            match back {
                Event::ProcessSpawn {
                    argv,
                    argv_truncated,
                    filename_truncated,
                    ..
                } => (argv, argv_truncated, filename_truncated),
                _ => panic!("expected ProcessSpawn"),
            }
        };
        let (argv, a, f) = decode(0);
        assert_eq!(argv, vec!["socat", "-d", "-d"]);
        assert_eq!((a, f), (false, false));
        let (_, a, f) = decode(spawn_trunc::ARGV);
        assert_eq!((a, f), (true, false));
        let (_, a, f) = decode(spawn_trunc::FILENAME);
        assert_eq!((a, f), (false, true));
        let (_, a, f) = decode(spawn_trunc::ARGV | spawn_trunc::FILENAME);
        assert_eq!((a, f), (true, true));
        // Bits the decoder does not know are ignored.
        let (_, a, f) = decode(0x80);
        assert_eq!((a, f), (false, false));
    }

    /// External audit EBPF-013: a ring-creation record with held counts
    /// carries one flood per budget; an ACTIVITY record or a record with
    /// nothing held carries none.
    #[test]
    fn io_uring_create_record_carries_its_floods() {
        let mut raw = crate::wire::IoUringRaw {
            timestamp_ns: 9,
            pid: 77,
            uid: 1000,
            comm: *b"looper\0\0\0\0\0\0\0\0\0\0",
            kind: crate::wire::IOURING_KIND_CREATE,
            last_opcode: 0,
            sq_thread: 0,
            _pad: 0,
            classes: 0,
            count: 8,
            _pad2: 0,
            held: 0,
            held_uid: 0,
        };
        assert!(io_uring_floods(&raw).iter().all(Option::is_none));
        raw.held = 300;
        raw.held_uid = 5;
        let [task, user] = io_uring_floods(&raw);
        match task {
            Some(Event::SensorFlood {
                source: FloodSource::IoUringCreate,
                pid: 77,
                uid: 1000,
                ref comm,
                held: 300,
                uid_level: false,
                timestamp_ns: 9,
                ..
            }) if comm == "looper" => {}
            other => panic!("unexpected {other:?}"),
        }
        assert!(matches!(
            user,
            Some(Event::SensorFlood {
                held: 5,
                uid_level: true,
                ..
            })
        ));
        raw.kind = crate::wire::IOURING_KIND_ACTIVITY;
        assert!(io_uring_floods(&raw).iter().all(Option::is_none));
    }

    /// The new variant's wire form, and an old record without `exe`.
    #[test]
    fn sensor_flood_serde_round_trips() {
        let [Some(e), None] = sensor_floods(FloodSource::Listen, 1, 2, "x", 3, 0, 4) else {
            panic!("one flood expected");
        };
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"listen\""));
        let back: Event = serde_json::from_str(&json).unwrap();
        assert_eq!(serde_json::to_string(&back).unwrap(), json);
        let legacy = json.replace(",\"exe\":null", "");
        assert_ne!(legacy, json);
        assert!(serde_json::from_str::<Event>(&legacy).is_ok());
    }
}
