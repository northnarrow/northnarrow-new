//! The export worker's part of the core ↔ worker protocol (lot 276, the
//! minimal signed export — R15's first step; `docs/operator/EXPORT.md`).
//!
//! The core reads its signed chains (the worker cannot: they are root's,
//! 0600 in 0700 directories) and hands the worker their rows, verbatim,
//! with each row's place in its chain; the worker turns each into OCSF
//! records and writes them to a sink — a rotating JSONL file, or syslog
//! over TLS — and says how many of the rows it was given are delivered.
//! The core advances its cursor by that many, never more: the chains are
//! the write-ahead log, delivery is at least once.
//!
//! Like the rest of the protocol, pure: the bounds below are checked by
//! both sides ([`super::ipc::Request::check`], [`super::ipc::check_response`]).
#![deny(clippy::string_slice, clippy::indexing_slicing)]

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::ipc::{Violation, MAX_FRAME};

/// Most rows one [`ExportRows`] request carries.
pub const MAX_EXPORT_ROWS: usize = 256;
/// Longest row the export hands over (a longer one is counted lost to the
/// export, stage 8: it would not fit a frame with its envelope).
pub const MAX_EXPORT_ROW: usize = 48 * 1024;
/// The bytes of a request's rows: a frame less room for the envelope.
pub const MAX_EXPORT_BYTES: usize = MAX_FRAME - 4 * 1024;
/// Longest a worker may spend on one request before it answers.
pub const MAX_EXPORT_BUDGET_MS: u32 = 3_000;
/// Largest CA bundle the setup carries.
pub const MAX_CA_PEM: usize = 32 * 1024;
/// Longest backoff a sink may name.
pub const MAX_RETRY_MS: u32 = 120_000;
/// Most OCSF records one row gives (a detection of a process: its finding
/// and the process's activity).
pub const MAX_RECORDS_PER_ROW: u32 = 2;

/// A chain the export reads: its name is the chain's kind (the files'
/// `KIND`, `docs/operator/EVIDENCE_CHAINS.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ExportChain {
    /// The detection records: OCSF Detection Finding.
    Detections,
    /// The actions chain's intents and outcomes (R12c): OCSF Remediation.
    Actions,
    /// The FIM drift: OCSF File System Activity.
    FimDrift,
    /// The network flows: OCSF Network Activity.
    Netflow,
    /// The canary accesses: OCSF File System, Process or Network Activity.
    CanaryAccess,
}

impl ExportChain {
    pub const ALL: [ExportChain; 5] = [
        ExportChain::Detections,
        ExportChain::Actions,
        ExportChain::FimDrift,
        ExportChain::Netflow,
        ExportChain::CanaryAccess,
    ];

    pub fn name(self) -> &'static str {
        match self {
            ExportChain::Detections => "detections",
            ExportChain::Actions => "actions",
            ExportChain::FimDrift => "fim_drift",
            ExportChain::Netflow => "netflow",
            ExportChain::CanaryAccess => "canary_access",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.name() == s)
    }

    /// Its files rotate into numbered archives (the flat canary chain is
    /// one file).
    pub fn rotates(self) -> bool {
        !matches!(self, ExportChain::CanaryAccess)
    }
}

/// Where the records go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ExportSink {
    /// JSONL files, rotated and bounded, in `/var/log/northnarrow/export`.
    File,
    /// RFC 5424 messages over TLS (RFC 5425).
    Syslog,
}

impl ExportSink {
    pub const ALL: [ExportSink; 2] = [ExportSink::File, ExportSink::Syslog];

    pub fn name(self) -> &'static str {
        match self {
            ExportSink::File => "file",
            ExportSink::Syslog => "syslog",
        }
    }
}

/// A receiver's address: an IP literal (the worker resolves no name).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportAddr {
    V4([u8; 4]),
    V6([u8; 16]),
}

/// The file sink's bounds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSetup {
    /// Bytes of one file before it rotates.
    pub max_bytes: u64,
    /// Files kept, the active one with them.
    pub max_files: u8,
}

/// The syslog receiver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyslogSetup {
    pub addr: ExportAddr,
    pub port: u16,
    /// The name its certificate must carry (a DNS name, or the IP).
    pub server_name: String,
    /// The CA certificates (PEM) the receiver's chain must end in; the
    /// signed configuration pins their SHA-256.
    pub ca_pem: Vec<u8>,
    /// RFC 5424 facility, 0..=23.
    pub facility: u8,
    /// The kernel's Landlock ABI handles TCP (4 or later): the worker must
    /// pin its connects to `port` before it connects, and say so.
    pub pin_port: bool,
}

/// The worker's configuration, sent once per worker (and again to a new
/// one).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportSetup {
    /// The agent's id, 32 lower-case hex digits.
    pub agent_id: String,
    /// The host's name for RFC 5424's HOSTNAME and OCSF's `device`: 1 to
    /// 255 printable ASCII characters, no space.
    pub hostname: String,
    /// The agent's version (`metadata.product.version`).
    pub version: String,
    /// The agent's public key: the worker checks each row's signature and
    /// says which do not verify.
    pub pubkey: [u8; 32],
    pub file: Option<FileSetup>,
    pub syslog: Option<SyslogSetup>,
}

/// A sink's state as the worker sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SinkState {
    /// Not configured.
    Off,
    /// Delivering.
    Up,
    /// A connection or a handshake in progress.
    Connecting,
    /// Failed; the worker retries after its backoff.
    Down,
    /// Cannot work as configured (no setup yet, a CA that does not parse,
    /// the file sink's directory missing): retried at the next setup.
    Failed,
}

impl SinkState {
    pub fn name(self) -> &'static str {
        match self {
            SinkState::Off => "off",
            SinkState::Up => "up",
            SinkState::Connecting => "connecting",
            SinkState::Down => "down",
            SinkState::Failed => "failed",
        }
    }
}

/// Why a TLS session failed (rustls' error, classified: a closed set, no
/// text from the worker).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsFault {
    /// The receiver's certificate did not verify (unknown CA, expired,
    /// another name).
    Certificate,
    /// The receiver sent an alert.
    Alert,
    /// The receiver broke the protocol (a malformed or unexpected message).
    Protocol,
    /// Anything else rustls reports.
    Other,
}

/// Why a sink is not delivering: a closed set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SinkFault {
    /// The worker has had no setup (it was restarted): the core sends one.
    NotSetUp,
    /// The TCP connect failed (errno).
    Connect(i32),
    /// No TCP connection within the budget.
    ConnectTimeout,
    /// No TLS session within its deadline.
    HandshakeTimeout,
    Tls(TlsFault),
    /// The receiver closed the connection.
    Closed,
    /// A read or write on the connection failed (errno).
    Io(i32),
    /// The receiver sent application data, or more than the worker reads.
    PeerData,
    /// The CA bundle holds no usable certificate, or the server name is
    /// not one.
    BadTrust,
    /// The file sink's directory or file could not be opened, written,
    /// synced or rotated (errno).
    File(i32),
    /// The connects could not be pinned to the receiver's port.
    Pin,
}

/// One signed row, verbatim (its line without the newline), and its place
/// in its chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportRow {
    /// The file of the chain: its archive number (the active file's is the
    /// number it will take); 0 for a flat chain.
    pub file: u64,
    /// The row's line in that file, from 1.
    pub line: u64,
    /// The byte offset its line ends at (past its newline).
    pub end: u64,
    pub raw: Vec<u8>,
    /// The terminator that sealed the previous file, verbatim, on the first
    /// row after a rotation: the link a receiver checks across it.
    pub rotate: Option<Vec<u8>>,
}

/// A row's place: its file and line ([`ExportRow`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RowPos {
    pub file: u64,
    pub line: u64,
}

impl ExportRow {
    pub fn pos(&self) -> RowPos {
        RowPos {
            file: self.file,
            line: self.line,
        }
    }
}

/// Rows of one chain for one sink: the rows after the last one the worker
/// said it committed (none: a poll of what it delivered since).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportRows {
    pub sink: ExportSink,
    pub chain: ExportChain,
    pub rows: Vec<ExportRow>,
    /// The most the worker may spend before it answers.
    pub budget_ms: u32,
}

/// What a setup gave.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportSetupOut {
    /// The worker's TCP connects are pinned to the receiver's port by a
    /// Landlock layer of their own — measured: a connect to another port
    /// was refused with `EACCES`.
    pub port_pinned: bool,
    pub file: SinkState,
    pub syslog: SinkState,
    pub fault: Option<SinkFault>,
}

/// What became of an [`ExportRows`] request: where the chain stands on
/// this sink.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportRowsOut {
    /// The newest row delivered, every row before it too: written and
    /// synced (file); acknowledged by the receiver's TCP and settled
    /// (syslog). The core moves its cursor to it.
    pub acked: Option<RowPos>,
    /// The newest row written into the sink (`>= acked`): the core sends
    /// the rows after it next, or again from its cursor when it goes back
    /// (a connection lost).
    pub committed: Option<RowPos>,
    /// The OCSF records of the rows delivered since the last answer.
    pub records: u32,
    /// Of those rows, the ones whose signature did not verify (exported,
    /// flagged).
    pub unverified: u32,
    pub state: SinkState,
    pub fault: Option<SinkFault>,
    /// When `Down`: the wait before the worker tries again.
    pub retry_ms: u32,
}

fn bad(what: &'static str) -> Result<(), Violation> {
    Err(Violation::Bounds(what))
}

/// 1 to 255 printable ASCII characters, no space (RFC 5424's
/// PRINTUSASCII).
pub fn hostname_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 255 && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

fn lower_hex32(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl ExportSetup {
    pub fn check(&self) -> Result<(), Violation> {
        if !lower_hex32(&self.agent_id) {
            return bad("export_setup: agent_id");
        }
        if !hostname_ok(&self.hostname) {
            return bad("export_setup: hostname");
        }
        if self.version.is_empty()
            || self.version.len() > 64
            || !self.version.bytes().all(|b| (0x21..=0x7e).contains(&b))
        {
            return bad("export_setup: version");
        }
        if self.file.is_none() && self.syslog.is_none() {
            return bad("export_setup: no sink");
        }
        if let Some(f) = &self.file {
            if !(1 << 20..=1 << 30).contains(&f.max_bytes) || !(1..=32).contains(&f.max_files) {
                return bad("export_setup: file bounds");
            }
        }
        if let Some(s) = &self.syslog {
            if s.port == 0
                || s.facility > 23
                || s.ca_pem.is_empty()
                || s.ca_pem.len() > MAX_CA_PEM
                || s.server_name.is_empty()
                || s.server_name.len() > 253
                || !s.server_name.bytes().all(|b| (0x21..=0x7e).contains(&b))
            {
                return bad("export_setup: syslog");
            }
        }
        Ok(())
    }
}

impl ExportRows {
    pub fn check(&self) -> Result<(), Violation> {
        if self.rows.len() > MAX_EXPORT_ROWS {
            return bad("export_rows: batch size");
        }
        if self.budget_ms == 0 || self.budget_ms > MAX_EXPORT_BUDGET_MS {
            return bad("export_rows: budget");
        }
        let mut bytes = 0usize;
        let mut last: Option<(u64, u64)> = None;
        for r in &self.rows {
            if r.raw.is_empty() || r.raw.len() > MAX_EXPORT_ROW {
                return bad("export_rows: a row's bytes");
            }
            if r.raw.contains(&b'\n') {
                return bad("export_rows: a row holds a newline");
            }
            if r.line == 0 || r.end == 0 {
                return bad("export_rows: a row's place");
            }
            if !self.chain.rotates() && (r.file != 0 || r.rotate.is_some()) {
                return bad("export_rows: a flat chain's row in a numbered file");
            }
            if let Some(t) = &r.rotate {
                if t.is_empty() || t.len() > MAX_EXPORT_ROW || r.line != 1 {
                    return bad("export_rows: a rotation's terminator");
                }
            }
            // in the chain's order, each row once
            if last.is_some_and(|l| (r.file, r.line) <= l) {
                return bad("export_rows: rows out of order");
            }
            last = Some((r.file, r.line));
            bytes += r.raw.len() + r.rotate.as_ref().map_or(0, Vec::len);
        }
        if bytes > MAX_EXPORT_BYTES {
            return bad("export_rows: the request's bytes");
        }
        Ok(())
    }
}

fn state_ok(configured: bool, s: SinkState) -> bool {
    configured != (s == SinkState::Off)
}

/// The core's check of a setup's answer.
pub fn check_setup_out(req: &ExportSetup, out: &ExportSetupOut) -> Result<(), Violation> {
    if !state_ok(req.file.is_some(), out.file) || !state_ok(req.syslog.is_some(), out.syslog) {
        return bad("export_setup: a sink's state");
    }
    // the pin was asked for (the kernel's Landlock handles TCP): a worker
    // that connects without it is refused — a fault that says it could not
    // pin is the only other honest answer, and then nothing connects
    if req.syslog.as_ref().is_some_and(|s| s.pin_port)
        && !out.port_pinned
        && !(out.fault == Some(SinkFault::Pin) && out.syslog == SinkState::Failed)
    {
        return bad("export_setup: the receiver's port is not pinned");
    }
    Ok(())
}

/// The core's check of an [`ExportRows`] answer, against the request
/// alone (the core checks it again against the rows it has sent: its
/// window).
pub fn check_rows_out(req: &ExportRows, out: &ExportRowsOut) -> Result<(), Violation> {
    match (out.acked, out.committed) {
        (Some(a), Some(c)) if a > c => return bad("export_rows: acked past committed"),
        (Some(_), None) => return bad("export_rows: acked, nothing committed"),
        _ => {}
    }
    if let (Some(c), Some(last)) = (out.committed, req.rows.last()) {
        if c > last.pos() {
            return bad("export_rows: committed past the rows sent");
        }
    }
    if req.sink == ExportSink::File && out.acked != out.committed {
        return bad("export_rows: a file write in flight");
    }
    if out.unverified > out.records {
        return bad("export_rows: unverified past the records");
    }
    if out.state == SinkState::Off {
        return bad("export_rows: a sink asked for says off");
    }
    if out.retry_ms > MAX_RETRY_MS {
        return bad("export_rows: retry");
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use alloc::vec;

    fn row(file: u64, line: u64) -> ExportRow {
        ExportRow {
            file,
            line,
            end: 100 * line,
            raw: b"{\"x\":1}".to_vec(),
            rotate: None,
        }
    }

    fn rows(chain: ExportChain, rows: Vec<ExportRow>) -> ExportRows {
        ExportRows {
            sink: ExportSink::Syslog,
            chain,
            rows,
            budget_ms: 1000,
        }
    }

    fn setup() -> ExportSetup {
        ExportSetup {
            agent_id: "0123456789abcdef0123456789abcdef".into(),
            hostname: "host-1".into(),
            version: "0.0.1".into(),
            pubkey: [7; 32],
            file: Some(FileSetup {
                max_bytes: 1 << 24,
                max_files: 4,
            }),
            syslog: Some(SyslogSetup {
                addr: ExportAddr::V4([127, 0, 0, 1]),
                port: 6514,
                server_name: "receiver.lab".into(),
                ca_pem: b"-----BEGIN CERTIFICATE-----".to_vec(),
                facility: 13,
                pin_port: true,
            }),
        }
    }

    #[test]
    fn names_round_trip() {
        for c in ExportChain::ALL {
            assert_eq!(ExportChain::from_name(c.name()), Some(c));
        }
        assert_eq!(ExportChain::from_name("audit"), None);
        assert!(!ExportChain::CanaryAccess.rotates());
        assert!(ExportChain::ALL
            .iter()
            .filter(|c| **c != ExportChain::CanaryAccess)
            .all(|c| c.rotates()));
        assert_eq!(ExportSink::File.name(), "file");
        assert_eq!(ExportSink::Syslog.name(), "syslog");
        assert_eq!(SinkState::Connecting.name(), "connecting");
    }

    #[test]
    fn a_conforming_request_passes_and_every_bound_is_checked() {
        let ok = rows(
            ExportChain::Detections,
            vec![row(1, 1), row(1, 2), row(2, 1)],
        );
        assert_eq!(ok.check(), Ok(()));
        // a poll: no row
        assert_eq!(rows(ExportChain::Detections, vec![]).check(), Ok(()));
        type Bend = fn(&mut ExportRows);
        let cases: Vec<(&str, Bend)> = vec![
            ("too many", |r| {
                r.rows = (1..=MAX_EXPORT_ROWS as u64 + 1)
                    .map(|l| row(1, l))
                    .collect()
            }),
            ("budget 0", |r| r.budget_ms = 0),
            ("budget", |r| r.budget_ms = MAX_EXPORT_BUDGET_MS + 1),
            ("empty row", |r| r.rows[0].raw.clear()),
            ("long row", |r| {
                r.rows[0].raw = vec![b'a'; MAX_EXPORT_ROW + 1]
            }),
            ("newline", |r| r.rows[0].raw = b"{}\n{}".to_vec()),
            ("line 0", |r| r.rows[0].line = 0),
            ("end 0", |r| r.rows[0].end = 0),
            ("order", |r| r.rows.swap(0, 1)),
            ("twice", |r| r.rows[1] = row(1, 1)),
            ("rotate not first", |r| {
                r.rows[1].rotate = Some(b"{}".to_vec())
            }),
            ("rotate empty", |r| {
                r.rows[2].rotate = Some(Vec::new());
            }),
            ("bytes", |r| {
                r.rows = (1..=3u64)
                    .map(|l| ExportRow {
                        raw: vec![b'a'; MAX_EXPORT_ROW],
                        ..row(1, l)
                    })
                    .collect()
            }),
        ];
        for (what, f) in cases {
            let mut r = ok.clone();
            f(&mut r);
            assert!(r.check().is_err(), "{what}");
        }
        // a rotation's terminator on the first row of the next file
        let mut r = ok.clone();
        r.rows[2].rotate = Some(b"{\"rotate\":{}}".to_vec());
        assert_eq!(r.check(), Ok(()));
        // the flat chain has one file, numbered 0, never rotated
        let flat = rows(ExportChain::CanaryAccess, vec![row(0, 1), row(0, 2)]);
        assert_eq!(flat.check(), Ok(()));
        let mut f = flat.clone();
        f.rows[0].file = 1;
        assert!(f.check().is_err());
        let mut f = flat;
        f.rows[0].rotate = Some(b"{}".to_vec());
        assert!(f.check().is_err());
        // the request's bytes: up to MAX_EXPORT_BYTES, a terminator's too
        let full = |extra: usize| {
            let mut r = rows(
                ExportChain::Detections,
                vec![
                    ExportRow {
                        raw: vec![b'a'; MAX_EXPORT_ROW],
                        ..row(1, 1)
                    },
                    ExportRow {
                        raw: vec![b'a'; MAX_EXPORT_BYTES - MAX_EXPORT_ROW - 2],
                        ..row(2, 1)
                    },
                ],
            );
            r.rows[1].rotate = Some(vec![b'r'; 2 + extra]);
            r
        };
        assert_eq!(full(0).check(), Ok(()));
        assert!(full(1).check().is_err(), "one byte past the bound");
    }

    #[test]
    fn a_setup_is_bounded() {
        assert_eq!(setup().check(), Ok(()));
        type Bend = fn(&mut ExportSetup);
        let cases: Vec<(&str, Bend)> = vec![
            ("agent id", |s| s.agent_id = "0123".into()),
            ("agent id case", |s| {
                s.agent_id = "0123456789ABCDEF0123456789abcdef".into()
            }),
            ("hostname", |s| s.hostname = "a b".into()),
            ("hostname empty", |s| s.hostname.clear()),
            ("version", |s| s.version.clear()),
            ("no sink", |s| {
                s.file = None;
                s.syslog = None;
            }),
            ("file bytes", |s| s.file.as_mut().unwrap().max_bytes = 1),
            ("file count", |s| s.file.as_mut().unwrap().max_files = 0),
            ("file count high", |s| {
                s.file.as_mut().unwrap().max_files = 33
            }),
            ("port", |s| s.syslog.as_mut().unwrap().port = 0),
            ("facility", |s| s.syslog.as_mut().unwrap().facility = 24),
            ("ca", |s| s.syslog.as_mut().unwrap().ca_pem.clear()),
            ("ca size", |s| {
                s.syslog.as_mut().unwrap().ca_pem = vec![b'a'; MAX_CA_PEM + 1]
            }),
            ("server name", |s| {
                s.syslog.as_mut().unwrap().server_name.clear()
            }),
            ("server name chars", |s| {
                s.syslog.as_mut().unwrap().server_name = "a\nb".into()
            }),
        ];
        for (what, f) in cases {
            let mut s = setup();
            f(&mut s);
            assert!(s.check().is_err(), "{what}");
        }
    }

    #[test]
    fn a_setup_s_answer_is_checked() {
        let s = setup();
        let ok = ExportSetupOut {
            port_pinned: true,
            file: SinkState::Up,
            syslog: SinkState::Connecting,
            fault: None,
        };
        assert_eq!(check_setup_out(&s, &ok), Ok(()));
        // a pin asked for and not made: refused, unless the worker says it
        // could not and connects nowhere
        let unpinned = ExportSetupOut {
            port_pinned: false,
            ..ok.clone()
        };
        assert!(check_setup_out(&s, &unpinned).is_err());
        let honest = ExportSetupOut {
            port_pinned: false,
            syslog: SinkState::Failed,
            fault: Some(SinkFault::Pin),
            ..ok.clone()
        };
        assert_eq!(check_setup_out(&s, &honest), Ok(()));
        let half = ExportSetupOut {
            syslog: SinkState::Up,
            ..honest
        };
        assert!(check_setup_out(&s, &half).is_err());
        // not asked for (an older kernel): no pin needed
        let mut old = setup();
        old.syslog.as_mut().unwrap().pin_port = false;
        assert_eq!(check_setup_out(&old, &unpinned), Ok(()));
        // a sink's state must say whether it is configured
        let mut no_file = setup();
        no_file.file = None;
        assert!(check_setup_out(&no_file, &ok).is_err());
        let off = ExportSetupOut {
            file: SinkState::Off,
            ..ok.clone()
        };
        assert!(check_setup_out(&s, &off).is_err());
        assert_eq!(check_setup_out(&no_file, &off), Ok(()));
    }

    #[test]
    fn a_rows_answer_is_checked() {
        let req = rows(ExportChain::Detections, vec![row(1, 1), row(1, 2)]);
        let at = |line| Some(RowPos { file: 1, line });
        let ok = ExportRowsOut {
            acked: at(1),
            committed: at(2),
            records: 2,
            unverified: 1,
            state: SinkState::Up,
            fault: None,
            retry_ms: 0,
        };
        assert_eq!(check_rows_out(&req, &ok), Ok(()));
        type Bend = fn(&mut ExportRowsOut);
        let cases: Vec<(&str, Bend)> = vec![
            ("committed past the rows", |o| {
                o.committed = Some(RowPos { file: 1, line: 3 })
            }),
            ("committed in a later file", |o| {
                o.committed = Some(RowPos { file: 2, line: 1 })
            }),
            ("acked past committed", |o| {
                o.acked = Some(RowPos { file: 1, line: 2 });
                o.committed = Some(RowPos { file: 1, line: 1 });
            }),
            ("acked without committed", |o| o.committed = None),
            ("unverified", |o| o.unverified = 3),
            ("off", |o| o.state = SinkState::Off),
            ("retry", |o| o.retry_ms = MAX_RETRY_MS + 1),
        ];
        for (what, f) in cases {
            let mut o = ok.clone();
            f(&mut o);
            assert!(check_rows_out(&req, &o).is_err(), "{what}");
        }
        // earlier rows' positions are within bounds, and a poll's answer
        // is bounded by the core's window, not by the request
        let none = ExportRowsOut {
            acked: None,
            committed: None,
            ..ok.clone()
        };
        assert_eq!(check_rows_out(&req, &none), Ok(()));
        let poll = rows(ExportChain::Detections, vec![]);
        assert_eq!(check_rows_out(&poll, &ok), Ok(()));
        // a file write is synced or not: nothing in flight
        let file = ExportRows {
            sink: ExportSink::File,
            ..req
        };
        assert!(check_rows_out(&file, &ok).is_err());
        let synced = ExportRowsOut {
            acked: at(2),
            committed: at(2),
            ..ok
        };
        assert_eq!(check_rows_out(&file, &synced), Ok(()));
    }

    #[test]
    fn hostnames_are_printusascii() {
        assert!(hostname_ok("a"));
        assert!(hostname_ok(&"a".repeat(255)));
        assert!(!hostname_ok(&"a".repeat(256)));
        assert!(!hostname_ok("é"));
        assert!(!hostname_ok("a\tb"));
    }
}
