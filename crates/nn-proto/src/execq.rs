//! Lab PR 223 (EXPERIMENTAL) — exec quarantine: the agent ↔
//! `northnarrow-scan` protocol and the signed hash list
//! (`execq-hashes.local`). Design: `docs/design/EXEC_QUARANTINE.md`.
//!
//! The scanner is a separate unprivileged process the agent spawns and
//! supervises. They talk over a `SOCK_SEQPACKET` socket pair, one postcard
//! message per packet ([`encode`], [`decode`]); a file travels as a
//! descriptor (`SCM_RIGHTS`), never as a path:
//!
//! 1. agent → scanner: [`ToScanner::Configure`] with a sealed memfd that
//!    holds the [`ScanConfig`] (the hash lists can exceed a packet);
//! 2. scanner → agent: [`FromScanner::Ready`] once its seccomp filter is in
//!    place;
//! 3. agent → scanner: [`ToScanner::Scan`] with the executable's descriptor,
//!    opened `O_RDONLY` by the agent; scanner → agent:
//!    [`FromScanner::Result`].

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Bumped on any incompatible change of the messages below.
pub const PROTOCOL_VERSION: u32 = 1;
/// Largest packet either side sends or accepts.
pub const MAX_PACKET: usize = 64 * 1024;
/// Largest [`ScanConfig`] the scanner reads from its memfd.
pub const MAX_CONFIG_BYTES: u64 = 16 << 20;
/// Longest label of a hash-list entry.
pub const MAX_LABEL: usize = 64;
/// Entries a hash list may hold.
pub const MAX_HASH_ENTRIES: usize = 100_000;
/// Default sum of heuristic weights from which a file is suspicious.
pub const DEFAULT_SUSPICIOUS_THRESHOLD: u32 = 3;
/// Default bytes of a file the scanner reads into memory for the format
/// heuristics (the hash always covers the whole file, up to
/// [`DEFAULT_MAX_HASH_BYTES`]).
pub const DEFAULT_MAX_READ_BYTES: u64 = 64 << 20;
/// Default largest file the scanner hashes; a larger one is `Unscanned`.
pub const DEFAULT_MAX_HASH_BYTES: u64 = 1 << 30;

/// Agent → scanner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToScanner {
    /// First message, with one descriptor: a sealed memfd of `config_len`
    /// bytes holding a postcard [`ScanConfig`].
    Configure { version: u32, config_len: u64 },
    /// Scan the file of the attached descriptor.
    Scan(ScanRequest),
}

/// Scanner → agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FromScanner {
    /// Configured and confined: requests are accepted from now on.
    Ready(ScannerHello),
    Result(ScanResult),
    /// The request could not be served (no descriptor, a descriptor that
    /// is not a regular file…).
    Refused {
        id: u64,
        reason: String,
    },
}

/// What the scanner applies. Built by the agent from the verified signed
/// overlays; the scanner opens no file to get it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanConfig {
    pub block: Vec<HashEntry>,
    pub allow: Vec<HashEntry>,
    pub suspicious_threshold: u32,
    pub max_read_bytes: u64,
    pub max_hash_bytes: u64,
    /// A signed YARA rule pack. Reserved: this release builds no YARA
    /// engine (`docs/design/EXEC_QUARANTINE.md` §6), the agent sends
    /// `None` and the scanner reports a pack it cannot apply.
    pub yara_rules: Option<Vec<u8>>,
}

/// One hash-list entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HashEntry {
    pub sha256: [u8; 32],
    pub label: String,
}

/// One file to scan (the descriptor travels with it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRequest {
    pub id: u64,
    /// `wire::execq::class` bits: where the file was executed from.
    pub class: u32,
    /// The path, for the reasons only (never opened); may be empty.
    pub path_hint: String,
}

/// What the scanner found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanVerdict {
    /// Nothing found.
    Clean,
    /// On the allow list.
    Trusted,
    /// The heuristics reached the threshold.
    Suspicious,
    /// On the block list.
    Malicious,
    /// The file could not be read whole (too large, an I/O error): no
    /// list could be checked.
    Unscanned,
}

impl ScanVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            ScanVerdict::Clean => "clean",
            ScanVerdict::Trusted => "trusted",
            ScanVerdict::Suspicious => "suspicious",
            ScanVerdict::Malicious => "malicious",
            ScanVerdict::Unscanned => "unscanned",
        }
    }
}

/// One explainable finding: a stable code, what it saw, and the weight it
/// adds towards [`ScanConfig::suspicious_threshold`] (0 for list hits and
/// notes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reason {
    pub code: String,
    pub detail: String,
    pub weight: u32,
}

impl Reason {
    pub fn new(code: &str, detail: impl Into<String>, weight: u32) -> Self {
        Self {
            code: code.to_string(),
            detail: detail.into(),
            weight,
        }
    }
}

/// The scanner's answer to one [`ScanRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanResult {
    pub id: u64,
    pub sha256: [u8; 32],
    pub size: u64,
    pub verdict: ScanVerdict,
    pub reasons: Vec<Reason>,
    /// `elf64-x86_64-dyn`, `script:/bin/sh`, `data`…
    pub format: String,
    /// Time spent on this file (µs).
    pub micros: u64,
}

/// The scanner's state once configured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannerHello {
    pub version: u32,
    /// Engine and version (`northnarrow-scan 0.0.1: sha256, lists, elf`).
    pub engine: String,
    pub uid: u32,
    /// The seccomp filter is installed (always, or the scanner exits).
    pub seccomp: bool,
    pub block_entries: u32,
    pub allow_entries: u32,
    /// What became of a YARA pack: `none`, `not built (N bytes ignored)`.
    pub yara: String,
}

/// postcard encoding of one message, refused above [`MAX_PACKET`].
pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, String> {
    let bytes = postcard::to_allocvec(msg).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_PACKET {
        return Err(alloc::format!(
            "message of {} bytes exceeds {MAX_PACKET}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

/// One message from a packet; trailing bytes are an error.
pub fn decode<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, String> {
    if bytes.len() > MAX_PACKET {
        return Err(alloc::format!("packet of {} bytes", bytes.len()));
    }
    let (v, rest) = postcard::take_from_bytes(bytes).map_err(|e| e.to_string())?;
    if !rest.is_empty() {
        return Err(alloc::format!("{} trailing bytes", rest.len()));
    }
    Ok(v)
}

/// [`ScanConfig`] for the memfd (no packet limit; [`MAX_CONFIG_BYTES`]).
pub fn encode_config(cfg: &ScanConfig) -> Result<Vec<u8>, String> {
    let bytes = postcard::to_allocvec(cfg).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(alloc::format!("config of {} bytes", bytes.len()));
    }
    Ok(bytes)
}

pub fn decode_config(bytes: &[u8]) -> Result<ScanConfig, String> {
    let (v, rest) = postcard::take_from_bytes(bytes).map_err(|e| e.to_string())?;
    if !rest.is_empty() {
        return Err(alloc::format!("{} trailing bytes", rest.len()));
    }
    Ok(v)
}

/// Lower-case hex of a digest.
pub fn hex32(d: &[u8; 32]) -> String {
    hex::encode(d)
}

// ── the signed hash list ────────────────────────────────────────────

/// The parsed `execq-hashes.local` overlay.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HashList {
    pub block: Vec<HashEntry>,
    pub allow: Vec<HashEntry>,
}

/// Parse the hash list. One entry per line:
///
/// ```text
/// # comment
/// block <sha256 hex> [label]
/// allow <sha256 hex> [label]
/// ```
///
/// The label (`[A-Za-z0-9._-]`, at most [`MAX_LABEL`]) names the entry in
/// records; without one the entry is `unlabelled`. Every malformed line is
/// an error — a signature must never cover content the loader would skip —
/// and so is a digest listed twice (in one list or in both).
pub fn parse_hash_list(text: &str) -> Result<HashList, String> {
    let mut out = HashList::default();
    let mut seen: alloc::collections::BTreeMap<[u8; 32], usize> =
        alloc::collections::BTreeMap::new();
    for (i, raw) in text.lines().enumerate() {
        let lineno = i + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let kind = fields.next().unwrap_or("");
        let digest = fields
            .next()
            .ok_or_else(|| alloc::format!("line {lineno}: `{kind}` without a sha256"))?;
        let label = fields.next().unwrap_or("unlabelled");
        if fields.next().is_some() {
            return Err(alloc::format!(
                "line {lineno}: more than `<block|allow> <sha256> [label]`"
            ));
        }
        let sha256 = parse_sha256(digest)
            .ok_or_else(|| alloc::format!("line {lineno}: `{digest}` is not 64 hex digits"))?;
        if !valid_label(label) {
            return Err(alloc::format!(
                "line {lineno}: label `{label}` (only A-Z a-z 0-9 . _ -, at most {MAX_LABEL})"
            ));
        }
        if let Some(first) = seen.insert(sha256, lineno) {
            return Err(alloc::format!(
                "line {lineno}: {digest} is already listed on line {first}"
            ));
        }
        let entry = HashEntry {
            sha256,
            label: label.to_string(),
        };
        match kind {
            "block" => out.block.push(entry),
            "allow" => out.allow.push(entry),
            other => {
                return Err(alloc::format!(
                    "line {lineno}: `{other}` (want `block` or `allow`)"
                ))
            }
        }
        if out.block.len() + out.allow.len() > MAX_HASH_ENTRIES {
            return Err(alloc::format!("more than {MAX_HASH_ENTRIES} entries"));
        }
    }
    Ok(out)
}

fn parse_sha256(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let v = hex::decode(s.to_ascii_lowercase()).ok()?;
    <[u8; 32]>::try_from(v.as_slice()).ok()
}

fn valid_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_LABEL
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    const B: &str = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752";

    #[test]
    fn a_list_parses_with_labels_and_comments() {
        let l = parse_hash_list(&alloc::format!(
            "# lab\nblock {A} nn-lab-test-elf\n\n  allow {} \n",
            B.to_ascii_uppercase()
        ))
        .unwrap();
        assert_eq!(l.block.len(), 1);
        assert_eq!(l.block[0].label, "nn-lab-test-elf");
        assert_eq!(hex32(&l.block[0].sha256), A);
        assert_eq!(l.allow[0].label, "unlabelled");
        assert_eq!(hex32(&l.allow[0].sha256), B);
    }

    #[test]
    fn every_malformed_line_is_refused() {
        for bad in [
            alloc::format!("deny {A}"),
            "block".to_string(),
            "block abc".to_string(),
            alloc::format!("block {A} two words"),
            alloc::format!("block {A} bad/label"),
            alloc::format!("block {A} {}", "x".repeat(MAX_LABEL + 1)),
            alloc::format!("block {A}\nallow {A}"),
            alloc::format!("block {A}\nblock {A} again"),
        ] {
            assert!(parse_hash_list(&bad).is_err(), "accepted: {bad}");
        }
    }

    #[test]
    fn messages_round_trip_and_are_bounded() {
        let req = ToScanner::Scan(ScanRequest {
            id: 7,
            class: 3,
            path_hint: "/tmp/x".into(),
        });
        let b = encode(&req).unwrap();
        assert_eq!(decode::<ToScanner>(&b).unwrap(), req);
        let mut long = b.clone();
        long.push(0);
        assert!(decode::<ToScanner>(&long).is_err(), "trailing bytes");
        let huge = ToScanner::Scan(ScanRequest {
            id: 1,
            class: 0,
            path_hint: "x".repeat(MAX_PACKET),
        });
        assert!(encode(&huge).is_err());
        let res = FromScanner::Result(ScanResult {
            id: 7,
            sha256: [1; 32],
            size: 10,
            verdict: ScanVerdict::Suspicious,
            reasons: alloc::vec![Reason::new("elf.upx_marker", "UPX! at 0xec", 3)],
            format: "elf64-x86_64-exec".into(),
            micros: 12,
        });
        assert_eq!(decode::<FromScanner>(&encode(&res).unwrap()).unwrap(), res);
        let cfg = ScanConfig {
            block: alloc::vec![HashEntry {
                sha256: [2; 32],
                label: "x".into()
            }],
            ..ScanConfig::default()
        };
        assert_eq!(decode_config(&encode_config(&cfg).unwrap()).unwrap(), cfg);
    }
}
