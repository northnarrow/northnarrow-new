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
/// Layout: timestamp + (dev,ino) target + (dev,ino) dest +
/// modifier triple + op byte + pad. **72 bytes**, 8-byte aligned.
/// Tappa 9 polish #3 (rename dest-path resolution) grew this
/// from 56 → 72 bytes by appending `dest_dev` + `dest_ino` for
/// `Renamed` events; older non-Rename emitters set both to 0.
/// The layout stays a strict superset of the Tappa 7
/// [`FsProtectDenialRaw`] prefix so the C4 drain decode logic
/// is still byte-symmetric on the leading 56 bytes.
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
    /// Polish #3 — rename DEST `(dev, ino)`. Populated by
    /// `fim_rename_observe` when the SOURCE inode is in
    /// WATCHED_PATHS (and the dest dentry's inode is reachable
    /// from the kernel hook args). Userland's drain then
    /// attempts to resolve `(dest_dev, dest_ino)` → path via
    /// [`crate::wire::InodeKey`]; success populates
    /// `FimEvent::dest_path` so the NN-L-FIM-010 rule (and
    /// future dest-aware rules) can match on the destination
    /// extension. Zero for non-Rename ops AND for renames
    /// where the kernel-side couldn't extract a dest inode.
    pub dest_dev: u64,
    pub dest_ino: u64,
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
            dest_dev: 0,
            dest_ino: 0,
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
    /// Tappa 9 polish #3 — DEST path for `Renamed` events when
    /// userland resolved `(dest_dev, dest_ino)` against the
    /// `InodePathMap`. `None` for non-rename events AND for
    /// renames where the dest inode wasn't in the map (e.g.,
    /// fresh dest inode not previously baselined). The NN-L-FIM-010
    /// ransomware rule checks BOTH `path` and `dest_path` against
    /// `RANSOMWARE_EXTENSIONS` so a watched file renamed TO
    /// `<path>.crypted` fires the rule. `#[serde(default)]`
    /// keeps pre-polish-#3 JSONL chains deserialisable.
    #[serde(default)]
    pub dest_path: Option<alloc::string::String>,
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

// ── Tappa 10 (N1) — Network Observability userland wire types ──────────
//
// Userland-decoded shapes for the Tappa 10 NetFlow / NetListener / TLS
// fingerprint subsystem. Std-only because they carry heap-allocated
// `String` + `Vec` + `IpAddr` fields — the kernel half consumes raw
// POD records (TcpConnectRaw, DnsQueryRaw, plus the new N2 BPF
// programs' raw structs once those ship). These three structs are
// what the agent's `net/*` drain + correlation layers emit into the
// rule engine, the audit chain (`netflow.jsonl`), and the nn-admin
// CLI responses (design §4 + §9).

/// Tappa 10 (N1) — userland-decoded TLS fingerprint extracted from
/// a ClientHello. Design §4.2.
///
/// JA3 + JA4 are the two industry-standard TLS client fingerprints
/// the N5 hand-rolled parser populates. `sni` and `alpn` are surfaced
/// alongside the hashes so detection rules can match on the cleartext
/// metadata without re-parsing the handshake. `ja3_raw` is the
/// pre-MD5 comma-separated tuple — operators see it via `nn-admin
/// net fingerprint` when chasing unknown fingerprints.
///
/// `None` SNI happens when the ClientHello lacks the SNI extension
/// (rare) or when extraction failed — kept distinct from `Some("")`.
#[cfg(feature = "std")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TlsFingerprint {
    /// JA3: `MD5(client_version,ciphers,extensions,curves,
    /// curve_formats)`. Standard 32-char hex form.
    pub ja3: alloc::string::String,
    /// JA3 raw pre-MD5 tuple. Operator-visible for debugging
    /// unknown fingerprints; same string the MD5 above is taken
    /// over.
    pub ja3_raw: alloc::string::String,
    /// JA4: `<protocol>_<version>_<cipher_count>_<extension_count>_
    /// <alpn>_<sha256_of_extensions>`. FoxIO / Salesforce 2023
    /// standard with better resistance to extension-reorder evasion.
    pub ja4: alloc::string::String,
    /// SNI server name (ClientHello extension 0). `None` when no
    /// SNI extension OR extraction failed.
    pub sni: Option<alloc::string::String>,
    /// ALPN protocol list (`h2`, `http/1.1`, …) advertised by the
    /// client. Empty if no ALPN extension.
    pub alpn: alloc::vec::Vec<alloc::string::String>,
}

/// Tappa 10 (N1) — userland-decoded TCP / UDP flow record. Design
/// §4.1.
///
/// One per (connect → close) pair on the TCP side (the N3 flow
/// tracker stitches connect kprobe + tcp_close kprobe by socket
/// cookie). UDP "flows" are synthetic — the N3 tracker emits one
/// record per `udp_sendmsg` family of outbound packets sharing the
/// same five-tuple within a short window. `end_ns = 0` means the
/// flow is still open at observation time (snapshot via `nn-admin
/// net flows` while a long-lived connection is alive).
///
/// `bytes_sent` / `bytes_recv` are populated from tcp_close's
/// `tcp_sock` struct; UDP records leave both as 0 (no per-socket
/// counter to harvest). `resolved_hostname` is filled by the N4
/// DNS attribution cache when the destination IP matches a recent
/// PID-keyed DNS answer; `None` for IP-literal destinations or
/// DNS-cache misses.
///
/// `flow_id` is the per-flow stable handle the operator references
/// via `nn-admin net fingerprint <flow_id>` — design §4.1 spec:
/// `SHA-256(start_ns || five_tuple || pid)[..16]`, hex.
#[cfg(feature = "std")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NetFlowEvent {
    /// Monotonic-clock ns since boot — connect (TCP) or first
    /// outbound packet (UDP).
    pub start_ns: u64,
    /// Monotonic-clock ns since boot — close (TCP) or end of the
    /// UDP burst window. `0` if still open at observation.
    pub end_ns: u64,
    /// `AF_INET` (2) or `AF_INET6` (10).
    pub family: u8,
    pub src_addr: std::net::IpAddr,
    pub src_port: u16,
    pub dst_addr: std::net::IpAddr,
    pub dst_port: u16,
    /// `IPPROTO_TCP` (6) or `IPPROTO_UDP` (17).
    pub proto: u8,
    pub pid: u32,
    pub uid: u32,
    pub comm: alloc::string::String,
    /// `/proc/<pid>/exe` at connect time, if resolvable.
    pub exe: Option<alloc::string::String>,
    /// Bytes sent on this socket (tcp_close `tp->bytes_sent`).
    /// 0 for UDP and for open snapshots.
    pub bytes_sent: u64,
    /// Bytes received on this socket. Same caveat as
    /// `bytes_sent`.
    pub bytes_recv: u64,
    /// DNS QNAME the N4 cache resolved `dst_addr` to within the
    /// §6 correlation window. `None` for IP-literal destinations
    /// or cache misses.
    pub resolved_hostname: Option<alloc::string::String>,
    /// JA3 / JA4 + SNI / ALPN extracted by the N5 parser post-
    /// handshake. `None` for non-TLS flows.
    pub tls_fingerprint: Option<TlsFingerprint>,
    /// Per-flow stable ID — `SHA-256(start_ns || five_tuple ||
    /// pid)[..16]` rendered as 32-char lowercase hex.
    pub flow_id: alloc::string::String,
}

/// Tappa 10 (N1) — userland-decoded `inet_csk_listen` event.
/// Design §4.3.
///
/// One per bind+listen transition. Snapshots emitted via
/// `nn-admin net listeners` are a point-in-time enumeration of
/// the in-process listener set the agent's N3 tracker maintains —
/// the kernel side surfaces add/remove deltas via the
/// `NET_LISTEN_EVENTS` ringbuf the N2 commit lands.
#[cfg(feature = "std")]
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NetListenerEvent {
    /// Monotonic-clock ns since boot — listen() transition.
    pub timestamp_ns: u64,
    /// `AF_INET` (2) or `AF_INET6` (10).
    pub family: u8,
    pub bind_addr: std::net::IpAddr,
    pub bind_port: u16,
    /// `IPPROTO_TCP` for TCP listeners. UDP "listeners" (bound
    /// recv sockets) reuse this same record shape with
    /// `proto = IPPROTO_UDP` (17).
    pub proto: u8,
    pub pid: u32,
    pub uid: u32,
    pub comm: alloc::string::String,
    pub exe: Option<alloc::string::String>,
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

    /// C1 (+ polish #3) test #1: [`FimDriftRaw`] layout matches
    /// the kernel↔userland ABI exactly. **72 bytes**, 8-aligned.
    /// Polish #3 grew this from 56 → 72 bytes by appending
    /// `dest_dev` + `dest_ino` (each `u64`) so
    /// `fim_rename_observe` can communicate the rename
    /// destination to userland. Wire-byte stability matters —
    /// any change here is a coordinated kernel+user upgrade.
    #[test]
    fn fim_drift_raw_layout_is_stable() {
        // 8 + 8 + 8 + 4 + 4 + 16 + 1 + 7 + 8 + 8 = 72 bytes,
        // 8-aligned.
        assert_eq!(size_of::<FimDriftRaw>(), 72);
        assert_eq!(align_of::<FimDriftRaw>(), 8);
        // FsProtectDenialRaw stays at the original 56-byte
        // shape; the FIM drift record is now a SUPERSET (first
        // 56 bytes identical, dest_dev + dest_ino appended).
        assert_eq!(size_of::<FsProtectDenialRaw>(), 56);
    }

    /// C1 (+ polish #3) test #2: [`FimDriftRaw`] bytemuck
    /// round-trip with the new dest fields populated. The
    /// kernel-side BPF serialises via `bytes_of`; userland
    /// decodes via `from_bytes`. Anchors the Pod/Zeroable
    /// derive on the expanded layout.
    #[test]
    fn fim_drift_raw_round_trips_via_bytes() {
        let original = FimDriftRaw {
            timestamp_ns: 1_700_000_000_000_000_000,
            target_dev: 0x800002,
            target_ino: 12345,
            modifier_pid: 42,
            modifier_uid: 0,
            modifier_comm: *b"sshd\0\0\0\0\0\0\0\0\0\0\0\0",
            op: FIM_OP_RENAMED,
            _pad: [0u8; 7],
            dest_dev: 0x800003,
            dest_ino: 67890,
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
        assert_eq!(restored.dest_dev, original.dest_dev);
        assert_eq!(restored.dest_ino, original.dest_ino);
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
            dest_path: None,
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

    /// Polish #3 test: pre-polish-#3 JSONL (no `dest_path` field)
    /// deserialises cleanly via `#[serde(default)]` → `None`. This
    /// anchors the forward-compat contract for the new field so a
    /// V1.0 agent loading a V1.1 chain (or vice-versa) doesn't
    /// reject rows.
    #[test]
    fn fim_event_serde_default_dest_path_on_legacy_row() {
        let legacy = serde_json::json!({
            "timestamp_ns": 1u64,
            "path": "/etc/passwd",
            "op": 1u8,
            "new_sha256": null,
            "baseline_sha256": null,
            "modifier_exe": null,
            "modifier_pid": 0u32,
            "modifier_uid": 0u32,
            "modifier_comm": "test",
            // dest_path INTENTIONALLY OMITTED — must default to None.
        });
        let parsed: FimEvent = serde_json::from_value(legacy).expect("legacy row must deserialise");
        assert_eq!(parsed.dest_path, None);
    }

    /// Polish #3 test: rename event with a resolved dest_path
    /// round-trips correctly — the rule layer reads
    /// `fe.dest_path.as_deref().unwrap_or("")` for the
    /// `ends_with(.crypted)` predicate.
    #[test]
    fn fim_event_serde_roundtrip_with_dest_path() {
        let original = FimEvent {
            timestamp_ns: 2_000_000_000,
            path: "/home/u/documents/quarterly.docx".to_string(),
            op: FimOp::Renamed,
            new_sha256: None,
            baseline_sha256: Some([0xCC; 32]),
            modifier_exe: None,
            modifier_pid: 99,
            modifier_uid: 1000,
            modifier_comm: "ransomware_loop".to_string(),
            dest_path: Some("/home/u/documents/quarterly.docx.crypted".to_string()),
        };
        let json = serde_json::to_string(&original).expect("serialize");
        let restored: FimEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, original);
        assert!(
            json.contains("/home/u/documents/quarterly.docx.crypted"),
            "dest_path must round-trip on the wire: {json}"
        );
    }

    // ── Tappa 10 N1 — Network Observability wire types ─────────────

    /// N1 test #1: [`TlsFingerprint`] CBOR round-trip. The fingerprint
    /// is what the N6 detection rules + N9 audit chain serialise; the
    /// admin protocol carries them inside `NetFingerprintResponse` so
    /// CBOR (not just JSON) determinism is on the critical path.
    /// Mirrors the cbor-determinism / round-trip pattern in
    /// `admin_signed_payload::tests::cbor_encoding_is_deterministic`.
    #[test]
    fn tls_fingerprint_serde_cbor_round_trip() {
        let original = TlsFingerprint {
            ja3: "771,4865-4866-4867,0-23-65281-10-11-35-16-5-13".to_string(),
            ja3_raw: "771,4865-4866-4867,0-23-65281-10-11-35-16-5-13,29-23-24,0".to_string(),
            ja4: "t13d1517h2_8daaf6152771_b1ff8ab2d16f".to_string(),
            sni: Some("example.com".to_string()),
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
        };
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&original, &mut buf).expect("cbor encode");
        // Determinism: two encodes of the same value land on the
        // same bytes. Load-bearing for any future netflow.jsonl
        // chain that hashes a fingerprint as part of an entry.
        let mut buf2 = Vec::new();
        ciborium::ser::into_writer(&original, &mut buf2).expect("cbor encode 2");
        assert_eq!(buf, buf2, "TlsFingerprint CBOR must be deterministic");
        let restored: TlsFingerprint =
            ciborium::de::from_reader(buf.as_slice()).expect("cbor decode");
        assert_eq!(restored, original);
    }

    /// N1 test #2: [`NetFlowEvent`] serde JSON round-trip. JSON is
    /// the on-disk format for `netflow.jsonl` (§4.4) and the
    /// streamed body of `NetFlowsResponse` (§9). Construct a fully-
    /// populated record (TLS flow with DNS attribution) so every
    /// optional field exercises the serde path.
    #[test]
    fn net_flow_event_serde_json_round_trip() {
        use std::net::{IpAddr, Ipv4Addr};
        let original = NetFlowEvent {
            start_ns: 1_700_000_000_000_000_000,
            end_ns: 1_700_000_000_500_000_000,
            family: 2, // AF_INET
            src_addr: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            src_port: 54321,
            dst_addr: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            dst_port: 443,
            proto: 6, // IPPROTO_TCP
            pid: 8888,
            uid: 0,
            comm: "curl".to_string(),
            exe: Some("/usr/bin/curl".to_string()),
            bytes_sent: 1234,
            bytes_recv: 5678,
            resolved_hostname: Some("example.com".to_string()),
            tls_fingerprint: Some(TlsFingerprint {
                ja3: "771,4865,0".to_string(),
                ja3_raw: "771,4865,0,29,0".to_string(),
                ja4: "t13d0000h2_0000_0000".to_string(),
                sni: Some("example.com".to_string()),
                alpn: vec!["h2".to_string()],
            }),
            flow_id: "9f3c1a2b4d5e6f70a1b2c3d4e5f60718".to_string(),
        };
        let json = serde_json::to_string(&original).expect("serialize");
        let restored: NetFlowEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, original);
        // Spot-check field presence so a reorder/rename in §4.1
        // surfaces here rather than silently in a downstream test.
        assert!(
            json.contains("\"flow_id\""),
            "flow_id must appear in JSON: {json}"
        );
        assert!(
            json.contains("\"resolved_hostname\""),
            "resolved_hostname must appear: {json}"
        );
        assert!(
            json.contains("\"tls_fingerprint\""),
            "tls_fingerprint must appear: {json}"
        );
    }

    /// N1 test #3: [`NetListenerEvent`] serde JSON round-trip.
    /// Same shape contract as the flow event — listener snapshots
    /// flow through `NetListenersResponse` as a streamed JSONL body
    /// per design §9.
    #[test]
    fn net_listener_event_serde_json_round_trip() {
        use std::net::{IpAddr, Ipv6Addr};
        let original = NetListenerEvent {
            timestamp_ns: 1_700_000_000_000_000_000,
            family: 10, // AF_INET6
            bind_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            bind_port: 22,
            proto: 6, // IPPROTO_TCP
            pid: 1234,
            uid: 0,
            comm: "sshd".to_string(),
            exe: Some("/usr/sbin/sshd".to_string()),
        };
        let json = serde_json::to_string(&original).expect("serialize");
        let restored: NetListenerEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, original);
    }
}
