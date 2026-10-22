//! The userland-decoded telemetry records: a FIM drift ([`FimEvent`],
//! [`FimOp`]), a network flow ([`NetFlowEvent`], [`FlowPhase`]), a listener
//! ([`NetListenerEvent`]) and a TLS fingerprint ([`TlsFingerprint`]).
//!
//! Wave 4 restructure, R02 (lab PR 240): the std types of
//! `common/src/wire/mod.rs`, moved as they were (their
//! `#[cfg(feature = "std")]` gates dropped: this crate is std) with their
//! tests; the raw layouts they are decoded from stay in `common::wire`.

// R02 shim: the raw constants and types of `common::wire` these items and
// their docs name, unqualified as they were in that module.
use common::wire::*;

/// Tappa 9 (C1) — userland-decoded FIM drift event. The drain
/// loop (C4) constructs one of these per kernel-observed drift
/// after resolving `(target_dev, target_ino)` → absolute path,
/// re-hashing the file, and diffing against the baseline.
///
/// Std-only because the userland-facing shape carries heap-
/// allocated `String` + `Option<[u8;32]>` fields. The eBPF
/// kernel half consumes only [`FimDriftRaw`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FimEvent {
    /// Monotonic-clock ns since boot — same source as
    /// [`ProcessSpawnRaw::timestamp_ns`].
    pub timestamp_ns: u64,
    /// The watched path that drifted. A file name that is not UTF-8
    /// is spelled with `\xNN` for each byte that is not, and `\\` for
    /// a backslash in that name; any other name is itself (external
    /// audit NN-AUD-291: the drain decoded it lossily, U+FFFD).
    pub path: alloc::string::String,
    pub op: FimOp,
    /// SHA-256 of the file's content AFTER the modification.
    /// `None` for `Deleted` / `Renamed` (target gone).
    pub new_sha256: Option<[u8; 32]>,
    /// Baseline SHA-256 the drift diverged from. `None` if the
    /// path was just added to the watch set and no baseline
    /// exists yet (operator forgot to re-baseline).
    pub baseline_sha256: Option<[u8; 32]>,
    /// Size in bytes of the file AFTER the modification, when the
    /// drain's re-hash probe could stat it. `None` for ops whose
    /// target is gone (`Deleted` / `Renamed`), for content-less
    /// events (`Opened` cred-reads), and when the probe failed.
    /// Paired with [`Self::baseline_size`] so a size-delta rule
    /// (NN-L-FIM-005's rsyslogd-append exemption) can distinguish
    /// an APPEND (file grew) from a TRUNCATION (file shrank).
    /// `#[serde(default)]` keeps pre-existing FIM event/JSONL
    /// chains deserialisable.
    #[serde(default)]
    pub new_size: Option<u64>,
    /// Size in bytes recorded in the baseline the drift diverged
    /// from. `None` when no baseline exists yet (path freshly
    /// watched) or the event carries no baseline. See
    /// [`Self::new_size`]; `#[serde(default)]` for forward-compat.
    #[serde(default)]
    pub baseline_size: Option<u64>,
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
    /// Tappa 9 (BUG-022) — `true` when `path` was reconstructed from
    /// a watched directory + a child leaf whose name overflowed
    /// [`FIM_CHILD_NAME_LEN`] (so the trailing extension was lost).
    /// The dir-rooted persistence rules treat a truncated child in
    /// their watched dir as a match even without the verifiable
    /// suffix — a >63-byte filename in `/lib/modules`,
    /// `/etc/systemd/system`, a `security/` dir, etc. is itself an
    /// indicator and must not be a bypass. `#[serde(default)]` keeps
    /// pre-BUG-022 JSONL chains deserialisable.
    #[serde(default)]
    pub child_truncated: bool,
    /// Tappa 10.9 step 1: an open found by the file-open sensor's
    /// credential-name table (every home), not by the operator's watch
    /// list. The FIM rules report it, and act on it only when another
    /// non-root user read it ([`Self::owner_uid`], design Q8): the
    /// owner's own tools (an editor, an SDK such as boto3) open these
    /// files too.
    #[serde(default)]
    pub wide_coverage: bool,
    /// Owner (uid) of the file a wide-coverage credential open read, when
    /// the path still named that inode. Q8, decided 2026-10-12: another
    /// user's read (not root's: backups) is acted on, not only reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_uid: Option<u32>,
    /// The reader of a wide-coverage credential open held
    /// `CAP_DAC_OVERRIDE` or `CAP_DAC_READ_SEARCH` in the initial user
    /// namespace: it reads every file as root does (a backup tool given
    /// the capability instead of root), so Q8 treats it as root.
    #[serde(default)]
    pub reader_dac_capable: bool,
    /// Review 86: the capability set on the file, for
    /// [`FimOp::CapabilitySet`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability: Option<FileCapability>,
    /// Wave 2 (TST-004): the mode, owner and group before and after, for
    /// [`FimOp::AttrChanged`], and (lab PR 229) for a [`FimOp::Modified`]
    /// whose mode or owner changed with its content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attrs: Option<FileAttrChange>,
    /// External audit NN-AUD-285 (FIMR-011): the file the event is about,
    /// as the drain found it — the watched inode itself, or, for a child
    /// created in or moved into a watched directory, the inode at the
    /// child's path once it was there. `None` when it could not be told:
    /// the child was not there yet, was already gone, or the name still
    /// held the file the operation replaces. NN-L-FIM-007 tells one edit
    /// (a temporary file renamed into place keeps its inode) from two
    /// drop-ins by it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_key: Option<InodeKey>,
    /// NN-AUD-285: the event is about a watched directory itself (the
    /// cron spool directory's own setattr), not a file in it.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub is_dir: bool,
    /// NN-AUD-285: the child was moved into the watched directory (a
    /// rename, reported as [`FimOp::Created`]), not created there.
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub moved_in: bool,
}

/// Wave 2 (TST-004): a watched file's permission bits and ownership, as
/// the baseline recorded them and as they are now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FileAttrChange {
    /// `st_mode & 0o7777` in the baseline.
    pub mode_before: u32,
    /// `st_mode & 0o7777` now.
    pub mode_after: u32,
    pub uid_before: u32,
    pub uid_after: u32,
    pub gid_before: u32,
    pub gid_after: u32,
}

impl FileAttrChange {
    const SET_ID: u32 = 0o6000;
    const GROUP_OTHER_WRITE: u32 = 0o022;
    const GROUP_OTHER_READ: u32 = 0o044;

    /// Permission bits set now that the baseline did not have.
    pub fn gained(&self) -> u32 {
        self.mode_after & !self.mode_before & 0o7777
    }

    pub fn owner_changed(&self) -> bool {
        self.uid_after != self.uid_before || self.gid_after != self.gid_before
    }

    /// A change that gives someone a power over the file they did not
    /// have: a set-uid/set-gid bit (it runs as its owner), write for group
    /// or others (they can replace it), or a new owner or group.
    pub fn grants_privilege(&self) -> bool {
        self.gained() & (Self::SET_ID | Self::GROUP_OTHER_WRITE) != 0 || self.owner_changed()
    }

    /// A change that lets more users read the file: read for group or
    /// others, or a new owner or group. What matters for a secret
    /// (`/etc/shadow`), not for a binary.
    pub fn exposes_content(&self) -> bool {
        self.gained() & Self::GROUP_OTHER_READ != 0 || self.owner_changed()
    }

    /// `mode 0o755 -> 0o4755 (set-uid added), uid 0 -> 1000`, for a
    /// verdict's reasoning.
    pub fn describe(&self) -> alloc::string::String {
        use alloc::format;
        let mut parts = alloc::vec::Vec::new();
        if self.mode_before != self.mode_after {
            let gained = self.gained();
            let mut what = alloc::vec::Vec::new();
            if gained & 0o4000 != 0 {
                what.push("set-uid added");
            }
            if gained & 0o2000 != 0 {
                what.push("set-gid added");
            }
            if gained & Self::GROUP_OTHER_WRITE != 0 {
                what.push("writable by group/others");
            }
            if gained & Self::GROUP_OTHER_READ != 0 {
                what.push("readable by group/others");
            }
            let note = if what.is_empty() {
                alloc::string::String::new()
            } else {
                format!(" ({})", what.join(", "))
            };
            parts.push(format!(
                "mode 0o{:o} -> 0o{:o}{note}",
                self.mode_before, self.mode_after
            ));
        }
        if self.uid_before != self.uid_after {
            parts.push(format!("uid {} -> {}", self.uid_before, self.uid_after));
        }
        if self.gid_before != self.gid_after {
            parts.push(format!("gid {} -> {}", self.gid_before, self.gid_after));
        }
        parts.join(", ")
    }
}

/// Review 86: a file capability as the kernel stored it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FileCapability {
    /// The permitted set: bit N is capability N.
    pub permitted: u64,
    /// The effective flag: the permitted set is raised at exec.
    pub effective: bool,
    /// A namespaced (revision 3) capability: it applies only inside a
    /// user namespace whose root is not the host's.
    pub namespaced: bool,
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
    /// Review 86: a file capability set on the file.
    CapabilitySet = FIM_OP_CAPABILITY_SET,
    /// Wave 2 (TST-004): mode, owner or group changed, content unchanged;
    /// what changed is in [`FimEvent::attrs`].
    AttrChanged = FIM_OP_ATTR_CHANGED,
}

impl From<FimOp> for u8 {
    fn from(op: FimOp) -> Self {
        op as u8
    }
}

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
            FIM_OP_CAPABILITY_SET => Ok(Self::CapabilitySet),
            FIM_OP_ATTR_CHANGED => Ok(Self::AttrChanged),
            other => Err(FimOpDecodeError::UnknownByte(other)),
        }
    }
}

/// Error path for [`FimOp::try_from`]. A future kernel running a
/// newer eBPF program could emit a `FIM_OP_*` constant this build
/// doesn't know about; userland surfaces it instead of panicking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FimOpDecodeError {
    UnknownByte(u8),
}

impl core::fmt::Display for FimOpDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FimOpDecodeError::UnknownByte(b) => {
                write!(f, "unknown FIM_OP discriminant byte: 0x{b:02x}")
            }
        }
    }
}

impl std::error::Error for FimOpDecodeError {}

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
    /// External audit NET-016: the start of the process `pid` named at
    /// connect time (`CLOCK_MONOTONIC` ns), or a time before it when only
    /// `/proc` knows it; 0 = unknown (the process gone before the connect
    /// was read, a row synthesised at close). The DNS attribution ignores
    /// queries older than this: a previous holder of the PID made them.
    #[serde(default)]
    pub proc_start_ns: u64,
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
    /// Tappa 10 (N3) — low 8 bits of `sock->sk_err` propagated
    /// from the kernel close event (see N2 [`NetFlowCloseRaw`]).
    /// `0` = graceful FIN (or UDP — no close semantics — or
    /// open-flow snapshot before the close arrived);
    /// `104` = `ECONNRESET` (RST received); `110` = `ETIMEDOUT`
    /// (keepalive timeout). N6 detection rules read this to
    /// distinguish "abrupt close" anomalies from clean
    /// connection teardown.
    ///
    /// `#[serde(default)]` keeps pre-N3 chains parseable —
    /// rows without the field deserialise to `close_reason: 0`,
    /// which matches the most common "graceful" case anyway.
    #[serde(default)]
    pub close_reason: u8,
    /// Lab PR 224 (CM-02): what this row is — the closed flow (the
    /// netflow log's row, as before), the flow judged at its connect, a
    /// periodic snapshot of a long-lived open flow, or a connect the
    /// `socket_connect` LSM refused. Rows of the open phases carry no
    /// byte counters, no close reason and no source end (the connect
    /// hook runs before the bind), and `flow_id` is empty: the canonical
    /// id needs the source the close reports. Rows written before the
    /// field read as [`FlowPhase::Closed`].
    #[serde(default)]
    pub phase: FlowPhase,
    /// Lab PR 224: when an open-phase row was observed (`CLOCK_MONOTONIC`
    /// ns): the connect for [`FlowPhase::Connect`] and
    /// [`FlowPhase::Denied`], the snapshot's time for
    /// [`FlowPhase::Snapshot`]; 0 for a closed row.
    #[serde(default)]
    pub observed_ns: u64,
}

/// Lab PR 224 (CM-02): the phase of a [`NetFlowEvent`].
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum FlowPhase {
    /// The flow is over (TCP close; a UDP send). The only phase written
    /// to `netflow.jsonl` and the only one the byte, beacon and
    /// record-only rules judge.
    #[default]
    Closed,
    /// Emitted at the TCP connect: the rules that need no byte count
    /// judge the flow while it is open (a reverse shell, a C2 session).
    Connect,
    /// A periodic re-evaluation of a TCP flow still open past the
    /// snapshot age, with the process's current image.
    Snapshot,
    /// A connect the `socket_connect` LSM refused (`--net-connect-deny`,
    /// destination in the operator blocklist): no flow exists.
    Denied,
}

impl FlowPhase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Connect => "connect",
            Self::Snapshot => "snapshot",
            Self::Denied => "denied",
        }
    }

    /// The flow is (or was refused while) open: no byte counters.
    pub fn is_open(&self) -> bool {
        !matches!(self, Self::Closed)
    }
}

/// Tappa 10 (N1) — userland-decoded `inet_csk_listen` event.
/// Design §4.3.
///
/// One per bind+listen transition. Snapshots emitted via
/// `nn-admin net listeners` are a point-in-time enumeration of
/// the in-process listener set the agent's N3 tracker maintains —
/// the kernel side surfaces add/remove deltas via the
/// `NET_LISTEN_EVENTS` ringbuf the N2 commit lands.
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

    #[test]
    fn fim_op_discriminants_lock_in() {
        assert_eq!(FimOp::Modified as u8, FIM_OP_MODIFIED);
        assert_eq!(FimOp::Created as u8, FIM_OP_CREATED);
        assert_eq!(FimOp::Deleted as u8, FIM_OP_DELETED);
        assert_eq!(FimOp::Renamed as u8, FIM_OP_RENAMED);
        assert_eq!(FimOp::Linked as u8, FIM_OP_LINKED);
        // C5.2 addition (APPENDED, byte 6).
        assert_eq!(FimOp::Opened as u8, FIM_OP_OPENED);
        // Review 86 addition (APPENDED, byte 7).
        assert_eq!(FimOp::CapabilitySet as u8, FIM_OP_CAPABILITY_SET);
        // Discriminant values are STABLE wire bytes — never
        // renumber. Anchor literal values.
        assert_eq!(FIM_OP_MODIFIED, 1);
        assert_eq!(FIM_OP_CREATED, 2);
        assert_eq!(FIM_OP_DELETED, 3);
        assert_eq!(FIM_OP_RENAMED, 4);
        assert_eq!(FIM_OP_LINKED, 5);
        assert_eq!(FIM_OP_OPENED, 6);
        assert_eq!(FIM_OP_CAPABILITY_SET, 7);
        assert_eq!(FIM_OP_ATTR_CHANGED, 8);
        assert_eq!(FimOp::AttrChanged as u8, FIM_OP_ATTR_CHANGED);
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
            FimOp::CapabilitySet,
            FimOp::AttrChanged,
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
            new_size: Some(4096),
            baseline_size: Some(2048),
            modifier_exe: Some("/usr/bin/dpkg".to_string()),
            modifier_pid: 42,
            modifier_uid: 0,
            modifier_comm: "dpkg".to_string(),
            dest_path: None,
            child_truncated: false,
            wide_coverage: false,
            owner_uid: None,
            reader_dac_capable: false,
            capability: None,
            attrs: None,
            file_key: None,
            is_dir: false,
            moved_in: false,
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
        // The size fields are also omitted by this legacy row and must
        // default to None (forward-compat contract for the NN-L-FIM-005
        // rsyslogd-append size-delta fields).
        assert_eq!(parsed.new_size, None);
        assert_eq!(parsed.baseline_size, None);
    }

    /// External audit NN-AUD-285: the file identity is optional on the
    /// wire — a row written before reads with none, an event without one
    /// writes the row it wrote before, and one with it round-trips.
    #[test]
    fn fim_event_file_identity_is_optional_on_the_wire() {
        let legacy = serde_json::json!({
            "timestamp_ns": 1u64,
            "path": "/etc/cron.d/job",
            "op": 2u8,
            "new_sha256": null,
            "baseline_sha256": null,
            "modifier_exe": null,
            "modifier_pid": 7u32,
            "modifier_uid": 0u32,
            "modifier_comm": "cp",
        });
        let mut parsed: FimEvent = serde_json::from_value(legacy).expect("legacy row");
        assert_eq!(parsed.file_key, None);
        assert!(!parsed.is_dir && !parsed.moved_in);
        let json = serde_json::to_string(&parsed).unwrap();
        for absent in ["file_key", "is_dir", "moved_in"] {
            assert!(!json.contains(absent), "{absent} written unset: {json}");
        }
        parsed.file_key = Some(InodeKey { dev: 8, ino: 1234 });
        parsed.is_dir = true;
        parsed.moved_in = true;
        let json = serde_json::to_string(&parsed).unwrap();
        assert!(
            json.contains(r#""file_key":{"dev":8,"ino":1234}"#),
            "{json}"
        );
        let back: FimEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, parsed);
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
            new_size: None,
            baseline_size: Some(8192),
            modifier_exe: None,
            modifier_pid: 99,
            modifier_uid: 1000,
            modifier_comm: "ransomware_loop".to_string(),
            dest_path: Some("/home/u/documents/quarterly.docx.crypted".to_string()),
            child_truncated: false,
            wide_coverage: false,
            owner_uid: None,
            reader_dac_capable: false,
            capability: None,
            attrs: None,
            file_key: None,
            is_dir: false,
            moved_in: false,
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
            proc_start_ns: 1_699_999_990_000_000_000,
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
            close_reason: 0,
            phase: FlowPhase::Snapshot,
            observed_ns: 1_700_000_000_400_000_000,
        };
        let json = serde_json::to_string(&original).expect("serialize");
        assert!(json.contains(r#""phase":"snapshot""#), "{json}");
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
        // External audit NET-016: a record written before the field
        // reads back with the start unknown.
        let older = json.replace("\"proc_start_ns\":1699999990000000000,", "");
        assert_ne!(older, json);
        let restored: NetFlowEvent = serde_json::from_str(&older).expect("older record");
        assert_eq!(restored.proc_start_ns, 0);
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
