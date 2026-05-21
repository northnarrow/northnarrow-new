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
    ADDR_LEN, FS_OP_IOCTL, FS_OP_RENAME, FS_OP_RMDIR, FS_OP_SETATTR, FS_OP_UNLINK,
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
    /// Pre-exec validation event (LSM `bprm_check_security`).
    ExecCheck {
        pid: u32,
        ppid: u32,
        uid: u32,
        comm: String,
        filename: String,
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
        query_name: String,
        query_type: u16,
        dns_server: [u8; ADDR_LEN],
        family: u8,
        timestamp_ns: u64,
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
        }
    }
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
        let mut len = raw.qname_len as usize;
        if len > raw.query_name.len() {
            len = raw.query_name.len();
        }
        let query_name = decode_dns_qname(&raw.query_name[..len]);
        Event::DnsQuery {
            pid: raw.pid,
            uid: raw.uid,
            comm: crate::wire::cstr_lossy(&raw.comm).into_owned(),
            query_name,
            query_type: raw.qtype,
            dns_server: raw.dns_server,
            family: raw.family,
            timestamp_ns: raw.timestamp_ns,
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
    let mut i = 0usize;
    while i < buf.len() {
        let len = buf[i] as usize;
        if len == 0 {
            break;
        }
        if len & 0xC0 != 0 {
            // compression pointer — give up cleanly
            out.push('…');
            break;
        }
        i += 1;
        let end = core::cmp::min(i + len, buf.len());
        if !out.is_empty() {
            out.push('.');
        }
        for &b in &buf[i..end] {
            out.push(if (32..127).contains(&b) {
                b as char
            } else {
                '?'
            });
        }
        if end == buf.len() {
            break;
        }
        i = end;
    }
    out
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
