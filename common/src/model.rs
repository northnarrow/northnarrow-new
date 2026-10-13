//! Userland event/verdict model.
//!
//! These are the rich, owned types the daemon and CLI manipulate.
//! Sensors convert raw kernel events (see [`crate::wire`]) into the
//! variants of [`Event`]; the decision engine produces a [`Verdict`]
//! describing what response the executors should run.

use alloc::string::String;
use serde::{Deserialize, Serialize};

use crate::wire::{
    DnsQueryRaw, ExecCheckRaw, FileOpenRaw, FsProtectDenialRaw, ProcessSpawnRaw, TcpConnectRaw,
    ADDR_LEN, FS_OP_BPF_LINK, FS_OP_BPF_MAP, FS_OP_IOCTL, FS_OP_KEXEC, FS_OP_PTRACE, FS_OP_RENAME,
    FS_OP_RMDIR, FS_OP_SETATTR, FS_OP_SIGNAL, FS_OP_UNLINK, FS_OP_WRITE,
};

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
    /// Wire byte the agent does not recognise (forward-compatible
    /// safety net).
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
            // Cluster 15.3 / R011: any non-zero byte from the BPF side
            // is "parent IS a kthread". Zero (the default for a BPF
            // read failure OR an older BPF that doesn't set this
            // field) decodes to `false` → R011 fail-secure path.
            parent_is_kthread: raw.parent_is_kthread != 0,
            exe: ExeIdentity::from_raw(&raw.exe),
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
    let mut comps: Vec<&str> = Vec::with_capacity(n);
    for i in 0..n {
        let s = &path[i * SLOT..i * SLOT + SLOT];
        let end = s.iter().position(|&b| b == 0).unwrap_or(SLOT);
        if end == 0 {
            continue;
        }
        if let Ok(c) = core::str::from_utf8(&s[..end]) {
            comps.push(c);
        }
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

/// Decode a DNS label-encoded QNAME (RFC 1035 §3.1) into dotted form.
///
/// Only handles uncompressed names — a compression pointer (high bits
/// `0b11_xx_xxxx`) terminates decoding and the partial result is
/// returned with a trailing `…`. Compression doesn't appear in
/// outbound queries from glibc/getaddrinfo, so this is fine for
/// Tappa 4 telemetry.
pub fn decode_dns_qname(buf: &[u8]) -> String {
    let mut out = String::new();
    for label in QnameLabels::new(buf) {
        match label {
            QnameLabel::Pointer => out.push('…'),
            QnameLabel::Data(bytes) => {
                if !out.is_empty() {
                    out.push('.');
                }
                for &b in bytes {
                    out.push(if (32..127).contains(&b) {
                        b as char
                    } else {
                        '?'
                    });
                }
            }
        }
    }
    out
}

/// One label of a DNS label-encoded name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QnameLabel<'a> {
    /// Label bytes (possibly cut short by the end of the buffer).
    Data(&'a [u8]),
    /// A compression pointer: decoding stops here.
    Pointer,
}

/// Allocation-free walk over the labels of a DNS name — the index
/// arithmetic of [`decode_dns_qname`], separated from the string building
/// so it can be model-checked (Kani, Tappa 10.8). Stops at the root label,
/// at a compression pointer, or at the end of the buffer.
pub struct QnameLabels<'a> {
    buf: &'a [u8],
    i: usize,
    done: bool,
}

impl<'a> QnameLabels<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            i: 0,
            done: false,
        }
    }
}

impl<'a> Iterator for QnameLabels<'a> {
    type Item = QnameLabel<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.i >= self.buf.len() {
            return None;
        }
        let len = self.buf[self.i] as usize;
        if len == 0 {
            self.done = true;
            return None;
        }
        if len & 0xC0 != 0 {
            // compression pointer — give up cleanly
            self.done = true;
            return Some(QnameLabel::Pointer);
        }
        let start = self.i + 1;
        let end = core::cmp::min(start + len, self.buf.len());
        let label = &self.buf[start..end];
        if end == self.buf.len() {
            self.done = true;
        }
        self.i = end;
        Some(QnameLabel::Data(label))
    }
}

/// Where a name ends in a wire buffer: the index just past its root label.
/// `None` when the buffer ends first (the name continues past what was
/// read) or a compression pointer stops the walk (a query's own name never
/// needs one). Tappa 10.9 step 3: the type follows at this index.
pub fn qname_wire_end(buf: &[u8]) -> Option<usize> {
    let mut labels = QnameLabels::new(buf);
    for label in labels.by_ref() {
        if label == QnameLabel::Pointer {
            return None;
        }
    }
    // The walk stopped at a root label (inside the buffer) or at its end.
    (labels.i < buf.len() && buf[labels.i] == 0).then_some(labels.i + 1)
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
    use crate::wire::{ProcessSpawnRaw, FILENAME_LEN, QNAME_LEN, TASK_COMM_LEN};

    #[test]
    fn decode_dns_qname_handles_basic_name() {
        // "\x07example\x03com\x00"
        let buf = b"\x07example\x03com\x00";
        assert_eq!(decode_dns_qname(buf), "example.com");
    }

    #[test]
    fn decode_dns_qname_handles_root_only() {
        let buf = b"\x00";
        assert_eq!(decode_dns_qname(buf), "");
    }

    #[test]
    fn decode_dns_qname_handles_compression_pointer_gracefully() {
        // Label "ns" then a compression pointer (bit 0xC0 set).
        let buf = b"\x02ns\xc0\x0c";
        let out = decode_dns_qname(buf);
        assert!(out.starts_with("ns"));
        assert!(out.contains('…'));
    }

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
            ("ab?cd.evil".into(), 1, false)
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
    fn qname_wire_end_finds_the_root_label() {
        assert_eq!(qname_wire_end(b"\x01a\x00\x00\x01"), Some(3));
        assert_eq!(qname_wire_end(b"\x00"), Some(1)); // the root name
        assert_eq!(qname_wire_end(b"\x01a"), None);
        assert_eq!(qname_wire_end(b""), None);
        assert_eq!(qname_wire_end(b"\x05ab"), None); // label cut by the end
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
                ..
            } => {
                assert!(argv.is_empty());
                assert_eq!(parent_comm, "");
                assert_eq!(parent_start_ns, 0);
            }
            _ => panic!("expected ProcessSpawn"),
        }
    }
}

/// Kani proofs (Tappa 10.8, "verifica formale dopo il fuzzing"): the
/// decoders that turn kernel-written bytes into events never panic, for
/// every possible input of the bounded size — fuzzing samples the input
/// space, these cover all of it.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    const N: usize = 16;

    /// The label walk behind `decode_dns_qname` (kernel-copied, attacker-
    /// written bytes) on any buffer of up to 16 bytes: no out-of-bounds
    /// index, every label inside the buffer, and it terminates — each step
    /// consumes at least one byte, so there are at most `len` labels.
    #[kani::proof]
    #[kani::unwind(18)]
    fn qname_label_walk_is_in_bounds_and_terminates() {
        let backing: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let buf = &backing[..len];
        let mut steps = 0usize;
        for label in QnameLabels::new(buf) {
            if let QnameLabel::Data(bytes) = label {
                assert!(bytes.len() <= len);
            }
            steps += 1;
            assert!(steps <= len);
        }
    }

    /// `qname_wire_end` on any buffer of up to 16 bytes: the end it reports
    /// is inside the buffer and just past a root label, so the type read
    /// after it (`From<&DnsQueryRaw>`) starts in bounds.
    #[kani::proof]
    #[kani::unwind(18)]
    fn qname_wire_end_is_past_a_root_label() {
        let backing: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let buf = &backing[..len];
        if let Some(end) = qname_wire_end(buf) {
            assert!(end >= 1 && end <= len);
            assert!(buf[end - 1] == 0);
        }
    }
}
