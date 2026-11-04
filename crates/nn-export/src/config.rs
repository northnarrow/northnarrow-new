//! The export's signed configuration (lot 276): `/etc/northnarrow/export.local`
//! and its `.sig`, an operator overlay (`nn-admin config overlay set export`,
//! signed by a `config-manage` key). **Off without it**: no file, or a file
//! that does not verify, and the agent exports nothing.
//!
//! The text is `key = value` lines (`#` starts a comment), every key known,
//! every value bounded:
//!
//! ```text
//! enabled = true
//! chain = detections          # repeated; none named: detections and actions
//! chain = actions
//! start = end                 # end (rows written from now) | oldest
//! file = on                   # the JSONL files in /var/log/northnarrow/export
//! file_max_bytes = 64MiB      # each file, 1MiB..1GiB
//! file_max_files = 4          # 1..32, the active file with them
//! syslog = 192.0.2.10:6514    # an IP and a port: the worker resolves no name
//! syslog_server_name = siem.example.org   # its certificate's name (default: the IP)
//! syslog_ca = /etc/northnarrow/export-ca.pem
//! syslog_ca_sha256 = <64 hex> # the CA file is pinned by the signed text
//! syslog_facility = 13        # 0..23 (13: log audit)
//! ```

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};
use nn_proto::ipc::{ExportChain, MAX_CA_PEM};

/// The chains exported when the configuration names none: the detections
/// and the actions. `netflow`, `fim_drift`, `canary_access` (who connected
/// where, which files changed, who read a canary) leave the host only when
/// the signed text names each (`docs/operator/EXPORT.md` §1a).
pub const DEFAULT_CHAINS: [ExportChain; 2] = [ExportChain::Detections, ExportChain::Actions];

/// The JSONL files' total at most (`file_max_bytes × file_max_files`).
pub const MAX_DIR_BYTES: u64 = 4 << 30;

/// The directory's bound the core holds the worker to: the files' total and
/// one record past each (a line longer than a file goes whole into an
/// empty one).
pub fn dir_bound(f: &FileConfig) -> u64 {
    u64::from(f.max_files) * file_bound(f)
}

/// One JSONL file at most: `file_max_bytes` and 1 MiB (the sink rotates
/// before a line would pass the size; a line longer than a file goes whole
/// into an empty one).
pub fn file_bound(f: &FileConfig) -> u64 {
    f.max_bytes + (1 << 20)
}

/// Where the overlay lives.
pub const EXPORT_LOCAL: &str = "/etc/northnarrow/export.local";

/// Where rows start when a sink first sees a chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Start {
    /// The rows written from the first start with the export on.
    End,
    /// Every row the chain still holds.
    Oldest,
}

impl Start {
    pub fn name(self) -> &'static str {
        match self {
            Start::End => "end",
            Start::Oldest => "oldest",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileConfig {
    pub max_bytes: u64,
    pub max_files: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyslogConfig {
    pub addr: SocketAddr,
    pub server_name: String,
    pub ca: PathBuf,
    pub ca_sha256: [u8; 32],
    pub facility: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportConfig {
    pub enabled: bool,
    pub chains: Vec<ExportChain>,
    pub start: Start,
    pub file: Option<FileConfig>,
    pub syslog: Option<SyslogConfig>,
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            chains: Vec::new(),
            start: Start::End,
            file: None,
            syslog: None,
        }
    }
}

pub const DEFAULT_FILE_MAX_BYTES: u64 = 64 << 20;
pub const DEFAULT_FILE_MAX_FILES: u8 = 4;
/// RFC 5424's "log audit".
pub const DEFAULT_FACILITY: u8 = 13;

fn parse_size(v: &str) -> Result<u64> {
    let (num, mult) = if let Some(n) = v.strip_suffix("GiB") {
        (n, 1u64 << 30)
    } else if let Some(n) = v.strip_suffix("MiB") {
        (n, 1 << 20)
    } else if let Some(n) = v.strip_suffix("KiB") {
        (n, 1 << 10)
    } else {
        (v, 1)
    };
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|_| anyhow!("`{v}` is not a size (a number, then KiB, MiB or GiB)"))?;
    n.checked_mul(mult)
        .ok_or_else(|| anyhow!("`{v}` is too large"))
}

fn ranged(v: &str, lo: u64, hi: u64, what: &str) -> Result<u64> {
    let n: u64 = v
        .parse()
        .map_err(|_| anyhow!("{what} `{v}` is not a number"))?;
    if !(lo..=hi).contains(&n) {
        bail!("{what} must be within {lo}..={hi} (got {n})");
    }
    Ok(n)
}

fn on_off(v: &str) -> Result<bool> {
    match v {
        "true" | "on" | "yes" => Ok(true),
        "false" | "off" | "no" => Ok(false),
        other => bail!("expected on or off (got `{other}`)"),
    }
}

/// A DNS name (letters, digits, hyphens, dots; labels of 1 to 63) or an IP
/// literal, as rustls takes a server name.
fn server_name_ok(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok()
        || (!s.is_empty()
            && s.len() <= 253
            && s.split('.').all(|l| {
                !l.is_empty()
                    && l.len() <= 63
                    && !l.starts_with('-')
                    && !l.ends_with('-')
                    && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }))
}

impl ExportConfig {
    /// Parse the overlay's text strictly (an unknown key, a value out of
    /// its bounds, a sink without what it needs: an error, never a guess).
    pub fn parse(text: &str) -> Result<Self> {
        let mut c = ExportConfig::default();
        let mut file = false;
        let mut max_bytes = DEFAULT_FILE_MAX_BYTES;
        let mut max_files = DEFAULT_FILE_MAX_FILES;
        let mut syslog: Option<SocketAddr> = None;
        let mut server_name: Option<String> = None;
        let mut ca: Option<PathBuf> = None;
        let mut ca_sha256: Option<[u8; 32]> = None;
        let mut facility = DEFAULT_FACILITY;
        let mut start = None;
        let mut enabled = None;
        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let at = |e: anyhow::Error| anyhow!("export.local:{}: {e}", lineno + 1);
            let (key, value) = line
                .split_once('=')
                .map(|(k, v)| (k.trim(), v.trim()))
                .ok_or_else(|| at(anyhow!("expected `key = value` (got `{line}`)")))?;
            let once = |seen: bool| {
                if seen {
                    Err(at(anyhow!("`{key}` given twice")))
                } else {
                    Ok(())
                }
            };
            match key {
                "enabled" => {
                    once(enabled.is_some())?;
                    enabled = Some(on_off(value).map_err(at)?);
                }
                "chain" => {
                    let ch = ExportChain::from_name(value).ok_or_else(|| {
                        at(anyhow!(
                            "no chain `{value}` (detections, actions, fim_drift, netflow, \
                             canary_access)"
                        ))
                    })?;
                    if c.chains.contains(&ch) {
                        return Err(at(anyhow!("chain `{value}` named twice")));
                    }
                    c.chains.push(ch);
                }
                "start" => {
                    once(start.is_some())?;
                    start = Some(match value {
                        "end" => Start::End,
                        "oldest" => Start::Oldest,
                        other => return Err(at(anyhow!("start is end or oldest (got `{other}`)"))),
                    });
                }
                "file" => file = on_off(value).map_err(at)?,
                "file_max_bytes" => {
                    max_bytes = parse_size(value).map_err(at)?;
                    if !(1 << 20..=1 << 30).contains(&max_bytes) {
                        return Err(at(anyhow!("file_max_bytes must be within 1MiB..1GiB")));
                    }
                }
                "file_max_files" => {
                    max_files = ranged(value, 1, 32, "file_max_files").map_err(at)? as u8
                }
                "syslog" => {
                    once(syslog.is_some())?;
                    let a: SocketAddr = value.parse().map_err(|_| {
                        at(anyhow!(
                            "syslog is an IP address and a port (`192.0.2.10:6514`, \
                             `[2001:db8::1]:6514`): the worker resolves no name (got `{value}`)"
                        ))
                    })?;
                    if a.port() == 0 || a.port() == 1 {
                        return Err(at(anyhow!("syslog's port must be above 1")));
                    }
                    if a.ip().is_unspecified() || a.ip().is_multicast() {
                        return Err(at(anyhow!("syslog's address must be a host's")));
                    }
                    syslog = Some(a);
                }
                "syslog_server_name" => {
                    once(server_name.is_some())?;
                    if !server_name_ok(value) {
                        return Err(at(anyhow!("`{value}` is not a DNS name or an IP")));
                    }
                    server_name = Some(value.to_ascii_lowercase());
                }
                "syslog_ca" => {
                    once(ca.is_some())?;
                    let p = PathBuf::from(value);
                    if !p.is_absolute()
                        || p.components()
                            .any(|c| matches!(c, std::path::Component::ParentDir))
                    {
                        return Err(at(anyhow!(
                            "syslog_ca must be an absolute path without `..`"
                        )));
                    }
                    ca = Some(p);
                }
                "syslog_ca_sha256" => {
                    once(ca_sha256.is_some())?;
                    let b = hex::decode(value)
                        .ok()
                        .and_then(|b| <[u8; 32]>::try_from(b).ok())
                        .filter(|_| value.len() == 64 && value == value.to_ascii_lowercase())
                        .ok_or_else(|| {
                            at(anyhow!("syslog_ca_sha256 is 64 lower-case hex digits"))
                        })?;
                    ca_sha256 = Some(b);
                }
                "syslog_facility" => {
                    facility = ranged(value, 0, 23, "syslog_facility").map_err(at)? as u8
                }
                other => {
                    return Err(at(anyhow!(
                        "unknown key `{other}` (enabled, chain, start, file, file_max_bytes, \
                         file_max_files, syslog, syslog_server_name, syslog_ca, \
                         syslog_ca_sha256, syslog_facility)"
                    )))
                }
            }
        }
        c.enabled = enabled.unwrap_or(false);
        c.start = start.unwrap_or(Start::End);
        if c.chains.is_empty() {
            // the default the least a host gives away (the review of #499,
            // D6, a product decision): the detections and the responses;
            // flows, file drift and canary reads only when named
            c.chains = DEFAULT_CHAINS.to_vec();
        }
        if file {
            // the directory's total, the rotation's bound (the review of
            // #499, D5): the export never fills the chains' disk
            if max_bytes.saturating_mul(u64::from(max_files)) > MAX_DIR_BYTES {
                bail!(
                    "export.local: file_max_bytes × file_max_files past {} GiB",
                    MAX_DIR_BYTES >> 30
                );
            }
            c.file = Some(FileConfig {
                max_bytes,
                max_files,
            });
        }
        match (syslog, ca, ca_sha256) {
            (Some(addr), Some(ca), Some(ca_sha256)) => {
                c.syslog = Some(SyslogConfig {
                    addr,
                    server_name: server_name.unwrap_or_else(|| addr.ip().to_string()),
                    ca,
                    ca_sha256,
                    facility,
                })
            }
            (Some(_), _, _) => bail!("export.local: syslog needs syslog_ca and syslog_ca_sha256"),
            (None, None, None) if server_name.is_none() => {}
            _ => bail!("export.local: syslog_* keys without `syslog`"),
        }
        if c.enabled && c.file.is_none() && c.syslog.is_none() {
            bail!("export.local: enabled with no sink (file = on, or syslog = <ip>:<port>)");
        }
        Ok(c)
    }

    /// For `nn-admin config overlay set|sign export`.
    pub fn validate(text: &str) -> Result<()> {
        Self::parse(text).map(|_| ())
    }

    /// The overlay in one line, for the journal and the status.
    pub fn summary(&self) -> String {
        let mut sinks = Vec::new();
        if let Some(f) = &self.file {
            sinks.push(format!(
                "file ({} × {} MiB)",
                f.max_files,
                f.max_bytes >> 20
            ));
        }
        if let Some(s) = &self.syslog {
            sinks.push(format!("syslog {} ({})", s.addr, s.server_name));
        }
        format!(
            "{} · chains {} · start {} · {}",
            if self.enabled { "on" } else { "off" },
            self.chains
                .iter()
                .map(|c| c.name())
                .collect::<Vec<_>>()
                .join(","),
            self.start.name(),
            if sinks.is_empty() {
                "no sink".to_string()
            } else {
                sinks.join(", ")
            }
        )
    }
}

/// The CA bundle the configuration names, read and checked against the
/// digest the signed text pins (a file changed after the signature, or
/// larger than a setup carries, is refused).
pub fn read_ca(path: &Path, sha256: &[u8; 32]) -> Result<Vec<u8>> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let at = |e: std::io::Error| anyhow!("{}: {e}", path.display());
    // not through a link, the file itself judged, at most one byte more
    // than a setup carries read
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(at)?;
    if !f.metadata().map_err(at)?.is_file() {
        bail!("{}: not a regular file", path.display());
    }
    let mut bytes = Vec::new();
    f.take(MAX_CA_PEM as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(at)?;
    if bytes.len() > MAX_CA_PEM {
        bail!(
            "{}: more than the {MAX_CA_PEM} bytes a setup carries",
            path.display()
        );
    }
    let got: [u8; 32] = Sha256::digest(&bytes).into();
    if &got != sha256 {
        bail!(
            "{}: its SHA-256 is {}, the signed configuration pins {}",
            path.display(),
            hex::encode(got),
            hex::encode(sha256)
        );
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "a3f1a3f1a3f1a3f1a3f1a3f1a3f1a3f1a3f1a3f1a3f1a3f1a3f1a3f1a3f1a3f1";

    /// A JSONL file at most its size and 1 MiB — a line longer than a file
    /// goes whole into an empty one (the sink's own test) — and the files
    /// together that, times their count: what the core holds the
    /// directory to (mutation MF1 of lot 276's run 7: the 1 MiB dropped).
    #[test]
    fn a_file_s_bound_holds_a_line_longer_than_the_file() {
        let f = FileConfig {
            max_bytes: 64 << 20,
            max_files: 4,
        };
        assert_eq!(file_bound(&f), (64 << 20) + (1 << 20));
        assert_eq!(dir_bound(&f), 4 * ((64 << 20) + (1 << 20)));
        // the sink at its smallest size: its files within that bound
        let d = tempfile::tempdir().unwrap();
        let small = FileConfig {
            max_bytes: 1 << 20,
            max_files: 2,
        };
        let mut s =
            crate::jsonl::JsonlSink::open(d.path(), small.max_bytes, small.max_files).unwrap();
        s.write(&[vec![b'x'; 2 * nn_proto::ipc::MAX_EXPORT_ROW + (1 << 19)]])
            .unwrap();
        s.write(&[vec![b'y'; (1 << 20) - 100]]).unwrap();
        for e in std::fs::read_dir(d.path()).unwrap() {
            let len = e.unwrap().metadata().unwrap().len();
            assert!(len <= file_bound(&small), "{len}");
        }
    }

    #[test]
    fn off_without_a_file_and_by_default() {
        let c = ExportConfig::parse("").unwrap();
        assert!(!c.enabled);
        assert_eq!(c.chains, DEFAULT_CHAINS.to_vec());
        // the default, by name (the review of #499, D6): the detections and
        // the actions — never the flows, the file drift, the canary reads
        assert_eq!(
            c.chains,
            vec![ExportChain::Detections, ExportChain::Actions]
        );
        assert_eq!(c.start, Start::End);
        assert!(c.file.is_none() && c.syslog.is_none());
        // a sink configured but not enabled: off
        assert!(!ExportConfig::parse("file = on").unwrap().enabled);
    }

    #[test]
    fn a_full_configuration_parses() {
        let text = format!(
            "enabled = true # on\nchain = detections\nchain = actions\nstart = oldest\n\
             file = on\nfile_max_bytes = 16MiB\nfile_max_files = 3\n\
             syslog = 10.0.0.5:6514\nsyslog_server_name = SIEM.example.org\n\
             syslog_ca = /etc/northnarrow/export-ca.pem\nsyslog_ca_sha256 = {SHA}\n\
             syslog_facility = 10\n"
        );
        let c = ExportConfig::parse(&text).unwrap();
        assert!(c.enabled);
        assert_eq!(
            c.chains,
            vec![ExportChain::Detections, ExportChain::Actions]
        );
        assert_eq!(c.start, Start::Oldest);
        assert_eq!(
            c.file,
            Some(FileConfig {
                max_bytes: 16 << 20,
                max_files: 3
            })
        );
        let s = c.syslog.as_ref().unwrap();
        assert_eq!(s.addr, "10.0.0.5:6514".parse().unwrap());
        assert_eq!(s.server_name, "siem.example.org");
        assert_eq!(s.facility, 10);
        assert_eq!(hex::encode(s.ca_sha256), SHA);
        assert!(c
            .summary()
            .contains("syslog 10.0.0.5:6514 (siem.example.org)"));
        // the server name defaults to the IP; v6 in brackets
        let c = ExportConfig::parse(&format!(
            "enabled = true\nsyslog = [2001:db8::1]:6514\nsyslog_ca = /a.pem\nsyslog_ca_sha256 = {SHA}"
        ))
        .unwrap();
        assert_eq!(c.syslog.unwrap().server_name, "2001:db8::1");
    }

    #[test]
    fn every_mistake_is_refused() {
        let ca = format!("syslog_ca = /a.pem\nsyslog_ca_sha256 = {SHA}\n");
        for (what, text) in [
            ("unknown key", "colour = blue".to_string()),
            ("no equals", "enabled".to_string()),
            (
                "enabled twice",
                "enabled = true\nenabled = false".to_string(),
            ),
            ("bad bool", "enabled = maybe".to_string()),
            ("bad chain", "chain = audit".to_string()),
            (
                "chain twice",
                "chain = actions\nchain = actions".to_string(),
            ),
            ("bad start", "start = now".to_string()),
            ("size small", "file_max_bytes = 1KiB".to_string()),
            ("size large", "file_max_bytes = 2GiB".to_string()),
            ("size junk", "file_max_bytes = lots".to_string()),
            ("files", "file_max_files = 33".to_string()),
            (
                "the directory's total past 4 GiB",
                "file = on\nfile_max_bytes = 1GiB\nfile_max_files = 5".to_string(),
            ),
            (
                "a name, not an IP",
                format!("syslog = siem.example.org:6514\n{ca}"),
            ),
            ("no port", format!("syslog = 10.0.0.5\n{ca}")),
            ("port 0", format!("syslog = 10.0.0.5:0\n{ca}")),
            ("unspecified", format!("syslog = 0.0.0.0:6514\n{ca}")),
            ("no ca", "syslog = 10.0.0.5:6514".to_string()),
            (
                "no ca digest",
                "syslog = 10.0.0.5:6514\nsyslog_ca = /a.pem".to_string(),
            ),
            (
                "relative ca",
                format!("syslog = 10.0.0.5:6514\nsyslog_ca = a.pem\nsyslog_ca_sha256 = {SHA}"),
            ),
            (
                "dotdot ca",
                format!(
                    "syslog = 10.0.0.5:6514\nsyslog_ca = /etc/../a.pem\nsyslog_ca_sha256 = {SHA}"
                ),
            ),
            (
                "short digest",
                "syslog = 10.0.0.5:6514\nsyslog_ca = /a.pem\nsyslog_ca_sha256 = abcd".to_string(),
            ),
            (
                "upper digest",
                format!(
                    "syslog = 10.0.0.5:6514\nsyslog_ca = /a.pem\nsyslog_ca_sha256 = {}",
                    SHA.to_uppercase()
                ),
            ),
            (
                "facility",
                format!("syslog = 10.0.0.5:6514\n{ca}syslog_facility = 24"),
            ),
            (
                "server name",
                format!("syslog = 10.0.0.5:6514\n{ca}syslog_server_name = a_b.example"),
            ),
            ("syslog keys alone", ca.clone()),
            ("enabled without a sink", "enabled = true".to_string()),
        ] {
            assert!(ExportConfig::parse(&text).is_err(), "{what}: {text}");
        }
    }

    #[test]
    fn the_ca_is_pinned_by_the_signed_digest() {
        use sha2::{Digest, Sha256};
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("ca.pem");
        std::fs::write(&p, b"-----BEGIN CERTIFICATE-----\n").unwrap();
        let good: [u8; 32] = Sha256::digest(b"-----BEGIN CERTIFICATE-----\n").into();
        assert!(read_ca(&p, &good).is_ok());
        assert!(read_ca(&p, &[0; 32])
            .unwrap_err()
            .to_string()
            .contains("pins"));
        std::fs::write(&p, vec![b'a'; MAX_CA_PEM + 1]).unwrap();
        assert!(read_ca(&p, &good).is_err());
        assert!(read_ca(&dir.path().join("none"), &good).is_err());
        assert!(read_ca(dir.path(), &good).is_err());
        // larger than a setup carries, its digest pinned all the same
        let big = dir.path().join("big.pem");
        let body = vec![b'a'; MAX_CA_PEM + 1];
        std::fs::write(&big, &body).unwrap();
        let sha: [u8; 32] = Sha256::digest(&body).into();
        let e = read_ca(&big, &sha).unwrap_err().to_string();
        assert!(e.contains("more than"), "{e}");
        let fits = &body[..MAX_CA_PEM];
        std::fs::write(&big, fits).unwrap();
        assert!(read_ca(&big, &Sha256::digest(fits).into()).is_ok());
        // through a link: refused
        std::fs::write(&p, b"-----BEGIN CERTIFICATE-----\n").unwrap();
        assert!(read_ca(&p, &good).is_ok());
        let link = dir.path().join("link.pem");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(read_ca(&link, &good).is_err());
    }
}
