//! Plain-Old-Data wire types that cross the kernel↔userland boundary.
//!
//! Every struct here is `#[repr(C)]`, fixed-size, contains only
//! primitive types or fixed arrays, and never holds a heap pointer.
//! Both the eBPF program and the userland sensor must agree on the
//! exact byte layout — bytemuck's `Pod`/`Zeroable` derives (userland
//! only, behind the `std` feature) provide a compile-time check that
//! the struct really is plain-old-data.

/// `TASK_COMM_LEN` — the fixed length of the kernel `comm` field.
pub const TASK_COMM_LEN: usize = 16;

/// Maximum length stored for the executable path. Paths longer than
/// this are truncated; they always end with a `\0` if there is room.
pub const FILENAME_LEN: usize = 256;

/// Maximum length of a DNS QNAME we record (RFC 1035 §2.3.4).
pub const QNAME_LEN: usize = 253;

/// IPv6 / padded-IPv4 address byte length.
pub const ADDR_LEN: usize = 16;

/// One process exec event as captured by the eBPF tracepoint.
///
/// Layout MUST stay identical between the eBPF program and userland.
/// Adding fields means coordinating both sides and bumping a version
/// constant if we ever add one.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct ProcessSpawnRaw {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub filename: [u8; FILENAME_LEN],
    pub timestamp_ns: u64,
}

impl ProcessSpawnRaw {
    /// Zeroed instance, suitable as a starting point inside an eBPF
    /// program where stack memory is not implicitly zero-initialised.
    pub const fn zeroed() -> Self {
        Self {
            pid: 0,
            ppid: 0,
            uid: 0,
            gid: 0,
            comm: [0u8; TASK_COMM_LEN],
            filename: [0u8; FILENAME_LEN],
            timestamp_ns: 0,
        }
    }
}

/// File open event (LSM `file_open` hook).
///
/// `flags` is the kernel `f_flags` (O_RDONLY etc.) at open time; it
/// is reduced to a `u32` because BPF helpers don't expose the full
/// `int` width portably across architectures.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct FileOpenRaw {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub flags: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub filename: [u8; FILENAME_LEN],
    pub timestamp_ns: u64,
}

impl FileOpenRaw {
    pub const fn zeroed() -> Self {
        Self {
            pid: 0,
            uid: 0,
            gid: 0,
            flags: 0,
            comm: [0u8; TASK_COMM_LEN],
            filename: [0u8; FILENAME_LEN],
            timestamp_ns: 0,
        }
    }
}

/// Pre-exec validation event (LSM `bprm_check_security`).
///
/// Distinct from `ProcessSpawnRaw` (post-exec tracepoint): this fires
/// before the new image runs, which is the kernel's last opportunity
/// to refuse the exec. Tappa 4 only emits telemetry; Tappa 7 will
/// turn this hook into an enforcement point.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct ExecCheckRaw {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub _pad0: u32,
    pub comm: [u8; TASK_COMM_LEN],
    pub filename: [u8; FILENAME_LEN],
    pub timestamp_ns: u64,
}

impl ExecCheckRaw {
    pub const fn zeroed() -> Self {
        Self {
            pid: 0,
            ppid: 0,
            uid: 0,
            _pad0: 0,
            comm: [0u8; TASK_COMM_LEN],
            filename: [0u8; FILENAME_LEN],
            timestamp_ns: 0,
        }
    }
}

/// Outbound TCP connect attempt (kprobe `tcp_v[46]_connect`).
///
/// `src_addr`/`dst_addr` are 16 bytes regardless of family: IPv4
/// addresses are stored in the first 4 bytes with the rest zeroed.
/// Ports are network-order shorts converted to host order before
/// emission so userland doesn't have to know.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct TcpConnectRaw {
    pub pid: u32,
    pub uid: u32,
    pub family: u8,
    pub _pad0: [u8; 1],
    pub src_port: u16,
    pub dst_port: u16,
    pub _pad1: [u8; 2],
    pub src_addr: [u8; ADDR_LEN],
    pub dst_addr: [u8; ADDR_LEN],
    pub comm: [u8; TASK_COMM_LEN],
    pub timestamp_ns: u64,
}

impl TcpConnectRaw {
    pub const fn zeroed() -> Self {
        Self {
            pid: 0,
            uid: 0,
            family: 0,
            _pad0: [0; 1],
            src_port: 0,
            dst_port: 0,
            _pad1: [0; 2],
            src_addr: [0; ADDR_LEN],
            dst_addr: [0; ADDR_LEN],
            comm: [0u8; TASK_COMM_LEN],
            timestamp_ns: 0,
        }
    }
}

/// DNS query (kprobe `udp_sendmsg` filtered to dest port 53).
///
/// `query_name` is the **raw label-encoded QNAME** copied from the
/// UDP payload — the userland sensor decodes it to dotted notation.
/// Doing the decoding outside eBPF keeps the verifier happy and the
/// hot path bounded.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct DnsQueryRaw {
    pub pid: u32,
    pub uid: u32,
    pub qtype: u16,
    pub _pad0: [u8; 2],
    pub dns_server: [u8; ADDR_LEN],
    pub family: u8,
    pub _pad1: [u8; 1],
    pub qname_len: u16,
    pub query_name: [u8; QNAME_LEN],
    pub _pad2: [u8; 3],
    pub comm: [u8; TASK_COMM_LEN],
    pub timestamp_ns: u64,
}

impl DnsQueryRaw {
    pub const fn zeroed() -> Self {
        Self {
            pid: 0,
            uid: 0,
            qtype: 0,
            _pad0: [0; 2],
            dns_server: [0; ADDR_LEN],
            family: 0,
            _pad1: [0; 1],
            qname_len: 0,
            query_name: [0u8; QNAME_LEN],
            _pad2: [0; 3],
            comm: [0u8; TASK_COMM_LEN],
            timestamp_ns: 0,
        }
    }
}

/// Composite key for the Tappa 7 `PROTECTED_INODES` BPF map.
///
/// Userland keys come from `stat(2)` (`st_dev`, `st_ino`); the eBPF
/// LSM hooks rebuild the same pair from `inode->i_sb->s_dev` and
/// `inode->i_ino`. We use `u64` for `dev` on both sides even though
/// the kernel `dev_t` is 32 bits — the wider type guarantees the
/// BPF map's key blob is naturally 8-aligned with no implicit pad.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct InodeKey {
    pub dev: u64,
    pub ino: u64,
}

// Tappa 7 filesystem-protection denial codes. The eBPF inode hooks
// write one of these into `FsProtectDenialRaw.operation` when they
// return `-EPERM`. Userland inflates the byte into the typed
// `model::FsProtectOperation`.
pub const FS_OP_UNLINK: u8 = 1;
pub const FS_OP_RMDIR: u8 = 2;
pub const FS_OP_RENAME: u8 = 3;
pub const FS_OP_SETATTR: u8 = 4;
pub const FS_OP_IOCTL: u8 = 5;

/// Audit record emitted whenever a Tappa 7 inode-protection LSM hook
/// returns `-EPERM`. The denial is the security event — userland
/// raises a WARN and feeds the agent's posture machine.
///
/// Field order chosen for natural u64 alignment with no implicit
/// padding gaps before `_pad`: 8 + 8 + 8 + 4 + 4 + 16 + 1 + 7 = 56.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct FsProtectDenialRaw {
    pub timestamp_ns: u64,
    pub target_dev: u64,
    pub target_ino: u64,
    pub attacker_pid: u32,
    pub attacker_uid: u32,
    pub attacker_comm: [u8; TASK_COMM_LEN],
    pub operation: u8,
    pub _pad: [u8; 7],
}

impl FsProtectDenialRaw {
    pub const fn zeroed() -> Self {
        Self {
            timestamp_ns: 0,
            target_dev: 0,
            target_ino: 0,
            attacker_pid: 0,
            attacker_uid: 0,
            attacker_comm: [0u8; TASK_COMM_LEN],
            operation: 0,
            _pad: [0u8; 7],
        }
    }
}

// Tappa 9 (C1) — FIM drift detection codes. The kernel-side
// observe-only LSM hooks (agent-ebpf/src/fim_watch.rs, C2) write
// one of these into `FimDriftRaw.op` when they reserve a ringbuf
// slot. Userland inflates the byte into the typed
// `wire::FimOp` enum.
//
// Discriminants are stable wire bytes — never renumber; appending
// only. Mirrors the Tappa 7 `FS_OP_*` style.
pub const FIM_OP_MODIFIED: u8 = 1;
pub const FIM_OP_CREATED: u8 = 2;
pub const FIM_OP_DELETED: u8 = 3;
pub const FIM_OP_RENAMED: u8 = 4;
pub const FIM_OP_LINKED: u8 = 5;
/// Tappa 9 (C5.2): `file_open` LSM observation. Emitted by
/// `fim_file_open_observe` on EVERY open of a watched inode
/// (read or write). Userland C5.3 cred-read rules classify
/// downstream — the BPF layer doesn't filter by access mode
/// since the WATCHED_PATHS set is already operator-curated.
pub const FIM_OP_OPENED: u8 = 6;

/// Tappa 9 (C1) — kernel↔userland record emitted by the FIM
/// observation hooks (design §5). One record per watched-inode
/// drift event. Userland's `agent/src/fim/drain.rs` (C4) decodes
/// these into the richer userland [`FimEvent`].
///
/// Layout: timestamp + (dev,ino) target + modifier triple + op
/// byte + pad. 56 bytes total, 8-byte aligned — identical shape
/// to Tappa 7's [`FsProtectDenialRaw`] by design (keeps the
/// ringbuf-record arithmetic symmetric, simplifies the C4 drain
/// loop's per-record decode).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
#[cfg_attr(feature = "std", derive(bytemuck::Pod, bytemuck::Zeroable))]
pub struct FimDriftRaw {
    pub timestamp_ns: u64,
    pub target_dev: u64,
    pub target_ino: u64,
    pub modifier_pid: u32,
    pub modifier_uid: u32,
    pub modifier_comm: [u8; TASK_COMM_LEN],
    /// One of the `FIM_OP_*` discriminants above. Inflated by
    /// userland into [`FimOp`].
    pub op: u8,
    pub _pad: [u8; 7],
}

impl FimDriftRaw {
    pub const fn zeroed() -> Self {
        Self {
            timestamp_ns: 0,
            target_dev: 0,
            target_ino: 0,
            modifier_pid: 0,
            modifier_uid: 0,
            modifier_comm: [0u8; TASK_COMM_LEN],
            op: 0,
            _pad: [0u8; 7],
        }
    }
}

/// Tappa 9 (C1) — userland-decoded FIM drift event. The drain
/// loop (C4) constructs one of these per kernel-observed drift
/// after resolving `(target_dev, target_ino)` → absolute path,
/// re-hashing the file, and diffing against the baseline.
///
/// Std-only because the userland-facing shape carries heap-
/// allocated `String` + `Option<[u8;32]>` fields. The eBPF
/// kernel half consumes only [`FimDriftRaw`].
#[cfg(feature = "std")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FimEvent {
    /// Monotonic-clock ns since boot — same source as
    /// [`ProcessSpawnRaw::timestamp_ns`].
    pub timestamp_ns: u64,
    /// The watched path that drifted. UTF-8 lossy — non-UTF-8
    /// paths are escaped (`\xNN`) rather than dropped.
    pub path: alloc::string::String,
    pub op: FimOp,
    /// SHA-256 of the file's content AFTER the modification.
    /// `None` for `Deleted` / `Renamed` (target gone).
    pub new_sha256: Option<[u8; 32]>,
    /// Baseline SHA-256 the drift diverged from. `None` if the
    /// path was just added to the watch set and no baseline
    /// exists yet (operator forgot to re-baseline).
    pub baseline_sha256: Option<[u8; 32]>,
    /// `/proc/<pid>/exe` of the modifying process if resolvable
    /// at decode time.
    pub modifier_exe: Option<alloc::string::String>,
    pub modifier_pid: u32,
    pub modifier_uid: u32,
    pub modifier_comm: alloc::string::String,
}

/// Tappa 9 (C1) — typed inflation of [`FimDriftRaw::op`]. Wire
/// bytes are the `FIM_OP_*` constants; the `serde(into = "u8",
/// try_from = "u8")` attribute pair makes the on-disk JSONL +
/// admin-wire form a bare integer rather than a string variant
/// (saves bytes on the chained baseline + drift logs).
///
/// Variant order MUST track the `FIM_OP_*` discriminant order —
/// asserted by the `fim_op_discriminants_lock_in` test in
/// `mod.rs::tests`.
#[cfg(feature = "std")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(into = "u8", try_from = "u8")]
#[repr(u8)]
pub enum FimOp {
    Modified = FIM_OP_MODIFIED,
    Created = FIM_OP_CREATED,
    Deleted = FIM_OP_DELETED,
    Renamed = FIM_OP_RENAMED,
    Linked = FIM_OP_LINKED,
    /// Tappa 9 (C5.2): emitted by `fim_file_open_observe`
    /// on every open of a watched inode. Drives C5.3
    /// cloud-credentials-read detection (NN-L-FIM-011..014).
    Opened = FIM_OP_OPENED,
}

#[cfg(feature = "std")]
impl From<FimOp> for u8 {
    fn from(op: FimOp) -> Self {
        op as u8
    }
}

#[cfg(feature = "std")]
impl core::convert::TryFrom<u8> for FimOp {
    type Error = FimOpDecodeError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            FIM_OP_MODIFIED => Ok(Self::Modified),
            FIM_OP_CREATED => Ok(Self::Created),
            FIM_OP_DELETED => Ok(Self::Deleted),
            FIM_OP_RENAMED => Ok(Self::Renamed),
            FIM_OP_LINKED => Ok(Self::Linked),
            FIM_OP_OPENED => Ok(Self::Opened),
            other => Err(FimOpDecodeError::UnknownByte(other)),
        }
    }
}

/// Error path for [`FimOp::try_from`]. A future kernel running a
/// newer eBPF program could emit a `FIM_OP_*` constant this build
/// doesn't know about; userland surfaces it instead of panicking.
#[cfg(feature = "std")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FimOpDecodeError {
    UnknownByte(u8),
}

#[cfg(feature = "std")]
impl core::fmt::Display for FimOpDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FimOpDecodeError::UnknownByte(b) => {
                write!(f, "unknown FIM_OP discriminant byte: 0x{b:02x}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FimOpDecodeError {}

/// nn-admin ↔ agent protocol carried over the Unix socket at
/// `/run/northnarrow/admin.sock`. Std-only because the agent is the
/// only consumer and `StatusResponse` references `PostureKind` which
/// lives behind `#[cfg(feature = "std")]` at the crate root.
#[cfg(feature = "std")]
pub mod admin_protocol;

/// Tappa 8 signed-payload value layer (operation code + nonce + ts +
/// agent_id + op-specific extra) plus the Ed25519 sign/verify
/// pipeline. Std-only because it pulls ciborium + ed25519-dalek +
/// sha2, all of which require `alloc`/std and are not needed by the
/// kernel eBPF half.
#[cfg(feature = "std")]
pub mod admin_signed_payload;

/// Decode a fixed-size, possibly NUL-terminated byte buffer into a
/// borrowed `&str`, stopping at the first NUL or at the end of the
/// buffer. Invalid UTF-8 is replaced lossily by the caller.
#[cfg(feature = "std")]
pub fn cstr_lossy(buf: &[u8]) -> alloc::borrow::Cow<'_, str> {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    alloc::string::String::from_utf8_lossy(&buf[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of};

    #[test]
    fn process_spawn_raw_layout_is_stable() {
        // 4 u32 + 16 + 256 + u64 = 16 + 16 + 256 + 8 = 296 bytes.
        // Aligned to 8 because of the trailing u64.
        assert_eq!(size_of::<ProcessSpawnRaw>(), 296);
        assert_eq!(align_of::<ProcessSpawnRaw>(), 8);
    }

    #[test]
    fn process_spawn_raw_round_trips_via_bytes() {
        let original = ProcessSpawnRaw {
            pid: 42,
            ppid: 7,
            uid: 1000,
            gid: 1000,
            comm: *b"ls\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            filename: {
                let mut f = [0u8; FILENAME_LEN];
                f[..8].copy_from_slice(b"/bin/ls\0");
                f
            },
            timestamp_ns: 1_700_000_000_000_000_000,
        };

        let bytes: &[u8] = bytemuck::bytes_of(&original);
        assert_eq!(bytes.len(), size_of::<ProcessSpawnRaw>());
        let restored: ProcessSpawnRaw = *bytemuck::from_bytes::<ProcessSpawnRaw>(bytes);
        assert_eq!(restored.pid, original.pid);
        assert_eq!(restored.ppid, original.ppid);
        assert_eq!(restored.uid, original.uid);
        assert_eq!(restored.gid, original.gid);
        assert_eq!(restored.comm, original.comm);
        assert_eq!(restored.filename, original.filename);
        assert_eq!(restored.timestamp_ns, original.timestamp_ns);
    }

    #[test]
    fn fs_protect_denial_raw_layout_is_stable() {
        // 8+8+8+4+4+16+1+7 = 56, aligned to 8.
        assert_eq!(size_of::<FsProtectDenialRaw>(), 56);
        assert_eq!(align_of::<FsProtectDenialRaw>(), 8);
    }

    #[test]
    fn cstr_lossy_stops_at_nul() {
        let mut buf = [0u8; 16];
        buf[..2].copy_from_slice(b"ls");
        let s = cstr_lossy(&buf);
        assert_eq!(s, "ls");

        let s = cstr_lossy(b"abc\0xyz");
        assert_eq!(s, "abc");

        let s = cstr_lossy(b"no-nul-here");
        assert_eq!(s, "no-nul-here");
    }

    // ── Tappa 9 C1 — FIM wire types ────────────────────────────────

    /// C1 test #1: [`FimDriftRaw`] layout matches the kernel↔userland
    /// ABI exactly. 56 bytes, 8-aligned, identical to
    /// [`FsProtectDenialRaw`] (Tappa 7's analogue). Wire-byte stability
    /// is the property — any drift here is a coordinated kernel+user
    /// upgrade.
    #[test]
    fn fim_drift_raw_layout_is_stable() {
        // 8 + 8 + 8 + 4 + 4 + 16 + 1 + 7 = 56 bytes, 8-aligned.
        assert_eq!(size_of::<FimDriftRaw>(), 56);
        assert_eq!(align_of::<FimDriftRaw>(), 8);
        // Same shape as Tappa 7's denial record (intentional —
        // simplifies the C4 drain-loop's per-record decode).
        assert_eq!(size_of::<FimDriftRaw>(), size_of::<FsProtectDenialRaw>());
    }

    /// C1 test #2: [`FimDriftRaw`] bytemuck round-trip. The eBPF
    /// kernel side serialises via `bytes_of`; userland decodes via
    /// `from_bytes`. Anchors the Pod/Zeroable derive.
    #[test]
    fn fim_drift_raw_round_trips_via_bytes() {
        let original = FimDriftRaw {
            timestamp_ns: 1_700_000_000_000_000_000,
            target_dev: 0x800002,
            target_ino: 12345,
            modifier_pid: 42,
            modifier_uid: 0,
            modifier_comm: *b"sshd\0\0\0\0\0\0\0\0\0\0\0\0",
            op: FIM_OP_MODIFIED,
            _pad: [0u8; 7],
        };
        let bytes: &[u8] = bytemuck::bytes_of(&original);
        assert_eq!(bytes.len(), size_of::<FimDriftRaw>());
        let restored: FimDriftRaw = *bytemuck::from_bytes::<FimDriftRaw>(bytes);
        assert_eq!(restored.timestamp_ns, original.timestamp_ns);
        assert_eq!(restored.target_dev, original.target_dev);
        assert_eq!(restored.target_ino, original.target_ino);
        assert_eq!(restored.modifier_pid, original.modifier_pid);
        assert_eq!(restored.modifier_comm, original.modifier_comm);
        assert_eq!(restored.op, original.op);
    }

    /// C1 test #3: [`FimOp`] discriminants lock in the wire bytes
    /// 1..=5. Variant order MUST track `FIM_OP_*` discriminant
    /// order — a reorder would silently change the byte semantics
    /// of every kernel-emitted `FimDriftRaw` record.
    #[test]
    fn fim_op_discriminants_lock_in() {
        assert_eq!(FimOp::Modified as u8, FIM_OP_MODIFIED);
        assert_eq!(FimOp::Created as u8, FIM_OP_CREATED);
        assert_eq!(FimOp::Deleted as u8, FIM_OP_DELETED);
        assert_eq!(FimOp::Renamed as u8, FIM_OP_RENAMED);
        assert_eq!(FimOp::Linked as u8, FIM_OP_LINKED);
        // C5.2 addition (APPENDED, byte 6).
        assert_eq!(FimOp::Opened as u8, FIM_OP_OPENED);
        // Discriminant values are STABLE wire bytes — never
        // renumber. Anchor literal values.
        assert_eq!(FIM_OP_MODIFIED, 1);
        assert_eq!(FIM_OP_CREATED, 2);
        assert_eq!(FIM_OP_DELETED, 3);
        assert_eq!(FIM_OP_RENAMED, 4);
        assert_eq!(FIM_OP_LINKED, 5);
        assert_eq!(FIM_OP_OPENED, 6);
    }

    /// C1 test #4: [`FimOp`] try_from round-trip + unknown-byte
    /// rejection. A future kernel could emit an op byte this build
    /// doesn't know about; userland surfaces it as
    /// [`FimOpDecodeError::UnknownByte`] instead of panicking.
    #[test]
    fn fim_op_try_from_round_trips_and_rejects_unknown() {
        use core::convert::TryFrom;
        for op in [
            FimOp::Modified,
            FimOp::Created,
            FimOp::Deleted,
            FimOp::Renamed,
            FimOp::Linked,
            FimOp::Opened,
        ] {
            let byte: u8 = op.into();
            let round: FimOp = FimOp::try_from(byte).expect("known byte must decode");
            assert_eq!(round, op);
        }
        // 0 is reserved (zeroed memory) — must reject.
        assert!(matches!(
            FimOp::try_from(0u8),
            Err(FimOpDecodeError::UnknownByte(0))
        ));
        // 99 simulates a future kernel emitting an unknown op.
        assert!(matches!(
            FimOp::try_from(99u8),
            Err(FimOpDecodeError::UnknownByte(99))
        ));
    }

    /// C1 test #5: [`FimEvent`] serde JSON round-trip. The
    /// userland-decoded event flows into the audit chain + `Event`
    /// channel; JSON serialisation is what the C3 baseline DB +
    /// C6 `nn-admin fim report --json` consume.
    #[test]
    fn fim_event_serde_json_round_trip() {
        let original = FimEvent {
            timestamp_ns: 1_700_000_000_000_000_000,
            path: "/usr/bin/sshd".to_string(),
            op: FimOp::Modified,
            new_sha256: Some([0xAA; 32]),
            baseline_sha256: Some([0xBB; 32]),
            modifier_exe: Some("/usr/bin/dpkg".to_string()),
            modifier_pid: 42,
            modifier_uid: 0,
            modifier_comm: "dpkg".to_string(),
        };
        let json = serde_json::to_string(&original).expect("serialize");
        let restored: FimEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, original);
        // op should serialise as a bare integer (serde(into="u8"))
        // — not a variant name string. Saves bytes in the chained
        // fim_drift.jsonl and matches the on-disk schema §4.1.
        assert!(
            json.contains(r#""op":1"#),
            "FimOp must serialise as integer wire byte; got: {json}"
        );
    }
}
