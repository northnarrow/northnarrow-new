//! External audit NET-017 (lab PR 207): the network blind spots, declared.
//!
//! The DNS rules (NN-L-NET-002, -004, -005, -014) read the queries sent to
//! UDP port 53 (the `dns_query` sensor), and nothing else. What escapes them
//! is counted and reported by `nn-admin net status`, not inspected:
//!
//! - **DNS over TLS.** The netflow rows to TCP/853, counted by the drain
//!   ([`note_flow`]), split by the sender's image: the local resolver's
//!   (systemd-resolved, unbound, stubby… — its upstream, when it runs DoT)
//!   and the other processes'. Another process speaking DoT resolves names
//!   past the resolver whose queries the DNS rules read.
//! - **QUIC.** The netflow rows to UDP/443 (HTTP/3). The TLS handshake runs
//!   inside QUIC's encrypted packets: no ClientHello can be read from them
//!   (no JA3, JA4 or SNI, even once a fingerprint producer exists, BUG-025).
//!   The rows still carry the addresses, the ports and the bytes, which the
//!   address rules judge.
//! - **systemd-resolved with `DNSOverTLS=` on** ([`resolver_dns_over_tls`]):
//!   its upstream queries leave on TCP/853, so a name resolved without a
//!   UDP/53 query of the process's own (`nss-resolve`, Varlink, D-Bus) is
//!   seen by no DNS rule. Read from `resolved.conf` and its drop-ins at boot
//!   (a WARN) and at each status request, so `net status` follows a change.
//!
//! Not covered, and said so: DNS over HTTPS (HTTPS to a resolver on TCP/443
//! looks like any web traffic: not counted, not inspected); ECH (TLS
//! extension `0xFE0D`, with the ClientHello producer, BUG-025); the per-link
//! DoT settings (networkd `.network` files, NetworkManager, `resolvectl
//! dnsovertls`) and a resolved built with another default than `no`, which
//! the file reader does not see — the TCP/853 count does.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use common::log_escape::Escaped;
use common::wire::NetFlowEvent;

/// DNS over TLS (RFC 7858).
pub const DOT_PORT: u16 = 853;
/// QUIC / HTTP/3 (RFC 9000, RFC 9114).
pub const QUIC_PORT: u16 = 443;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// The netflow rows the DNS and TLS readers cannot see into, since boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EncryptedFlows {
    /// Rows to TCP/853 (DNS over TLS).
    pub dot: u64,
    /// Of those, the rows of a known local resolver program, by image.
    pub dot_resolver: u64,
    /// Rows to UDP/443 (QUIC).
    pub quic: u64,
}

/// The counters behind [`EncryptedFlows`] (one process-wide instance; a
/// test makes its own).
#[derive(Debug, Default)]
pub struct EncryptedFlowCounters {
    dot: AtomicU64,
    dot_resolver: AtomicU64,
    quic: AtomicU64,
}

impl EncryptedFlowCounters {
    pub const fn new() -> Self {
        Self {
            dot: AtomicU64::new(0),
            dot_resolver: AtomicU64::new(0),
            quic: AtomicU64::new(0),
        }
    }

    /// Count one netflow row: its protocol, its destination port, and the
    /// sender's image (`None` is not a resolver).
    pub fn note(&self, proto: u8, dst_port: u16, exe: Option<&str>) {
        match (proto, dst_port) {
            (IPPROTO_TCP, DOT_PORT) => {
                self.dot.fetch_add(1, Ordering::SeqCst);
                if crate::decision::rules::net::sender_is_forwarder(exe) {
                    self.dot_resolver.fetch_add(1, Ordering::SeqCst);
                }
            }
            (IPPROTO_UDP, QUIC_PORT) => {
                self.quic.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    /// The resolver's count is read first: [`Self::note`] adds to the total
    /// first, so the snapshot's resolver rows never exceed its total.
    pub fn snapshot(&self) -> EncryptedFlows {
        let dot_resolver = self.dot_resolver.load(Ordering::SeqCst);
        EncryptedFlows {
            dot: self.dot.load(Ordering::SeqCst),
            dot_resolver,
            quic: self.quic.load(Ordering::Relaxed),
        }
    }
}

static COUNTERS: EncryptedFlowCounters = EncryptedFlowCounters::new();

/// The drain counts every netflow row it records (held back from the rules
/// or not).
pub fn note_flow(ev: &NetFlowEvent) {
    COUNTERS.note(ev.proto, ev.dst_port, ev.exe.as_deref());
}

/// Since boot, for the status reply.
pub fn encrypted_flows() -> EncryptedFlows {
    COUNTERS.snapshot()
}

// ── systemd-resolved's DNSOverTLS= ───────────────────────────────────

/// `DNSOverTLS=` when it is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DotMode {
    /// `yes` (or another true boolean): every upstream query over TLS.
    Yes,
    /// Over TLS when the server offers it, plain DNS otherwise.
    Opportunistic,
}

/// systemd-resolved's global DoT setting, with the file that set it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverDot {
    pub mode: DotMode,
    pub source: PathBuf,
}

/// The directories of `systemd/resolved.conf` and `resolved.conf.d`,
/// highest priority first (systemd.syntax(7), "Configuration Directories
/// and Precedence"), relative to the root.
const CONF_DIRS: [&str; 4] = [
    "etc/systemd",
    "run/systemd",
    "usr/local/lib/systemd",
    "usr/lib/systemd",
];
/// A configuration file is read up to this size (resolved's is ~1 KiB).
const MAX_CONF_BYTES: u64 = 64 * 1024;
/// Entries read per drop-in directory.
const MAX_DROPINS_PER_DIR: usize = 256;

/// systemd-resolved's `DNSOverTLS=` from the files on this host, `None`
/// when it is off (absent, `no`, empty) or nothing configures resolved.
pub fn resolver_dns_over_tls() -> Option<ResolverDot> {
    resolver_dns_over_tls_under(Path::new("/"))
}

/// [`resolver_dns_over_tls`] with the files under `root`. The order is
/// resolved's: the main file (the first of the four directories that has
/// one), then the drop-ins by file name — a name in a higher directory
/// hides the same name in a lower one, a link to `/dev/null` masks it — and
/// the last valid assignment in the `[Resolve]` section wins; an empty value
/// resets to the default (`no`), an invalid one is ignored.
pub fn resolver_dns_over_tls_under(root: &Path) -> Option<ResolverDot> {
    let mut files = Vec::new();
    if let Some(main) = CONF_DIRS
        .iter()
        .map(|d| root.join(d).join("resolved.conf"))
        .find(|p| p.symlink_metadata().is_ok())
    {
        files.push(main);
    }
    let mut dropins: BTreeMap<OsString, PathBuf> = BTreeMap::new();
    for dir in CONF_DIRS.iter().rev() {
        let Ok(entries) = std::fs::read_dir(root.join(dir).join("resolved.conf.d")) else {
            continue;
        };
        for entry in entries.flatten().take(MAX_DROPINS_PER_DIR) {
            let name = entry.file_name();
            if name.as_bytes().ends_with(b".conf") {
                dropins.insert(name, entry.path());
            }
        }
    }
    files.extend(dropins.into_values());

    let mut state = None;
    for file in files {
        let Some(body) = read_conf(&file) else {
            continue;
        };
        for value in dns_over_tls_values(&body) {
            match parse_dot_mode(&value) {
                Some(Some(mode)) => {
                    state = Some(ResolverDot {
                        mode,
                        source: file.clone(),
                    })
                }
                Some(None) => state = None,
                None => {}
            }
        }
    }
    state
}

/// A regular file's first [`MAX_CONF_BYTES`], or `None`: absent,
/// unreadable, or not a regular file (`/dev/null`, the mask; a FIFO is
/// opened non-blocking and skipped).
fn read_conf(path: &Path) -> Option<String> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .ok()?;
    if !f.metadata().ok()?.is_file() {
        return None;
    }
    let mut buf = Vec::new();
    f.take(MAX_CONF_BYTES).read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).into_owned())
}

/// The values of the `DNSOverTLS=` assignments in the `[Resolve]` section,
/// in order. systemd's syntax: `#` and `;` start a comment line, a trailing
/// `\` continues the line, key and value are trimmed, keys are
/// case-sensitive.
fn dns_over_tls_values(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_resolve = false;
    let mut pending = String::new();
    for raw in body.lines() {
        if let Some(head) = raw.strip_suffix('\\') {
            pending.push_str(head);
            pending.push(' ');
            continue;
        }
        pending.push_str(raw);
        let line = std::mem::take(&mut pending);
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            in_resolve = line == "[Resolve]";
            continue;
        }
        if !in_resolve {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            if key.trim() == "DNSOverTLS" {
                out.push(value.trim().to_string());
            }
        }
    }
    out
}

/// resolved's `dns_over_tls_mode_from_string`: a boolean first (systemd's
/// `parse_boolean`, case-insensitive), then `opportunistic`. `Some(None)`:
/// off (false, or empty: the default). `None`: invalid, ignored.
fn parse_dot_mode(value: &str) -> Option<Option<DotMode>> {
    if value.is_empty() {
        return Some(None);
    }
    let v = value.to_ascii_lowercase();
    match v.as_str() {
        "1" | "yes" | "y" | "true" | "t" | "on" => Some(Some(DotMode::Yes)),
        "0" | "no" | "n" | "false" | "f" | "off" => Some(None),
        _ if value == "opportunistic" => Some(Some(DotMode::Opportunistic)),
        _ => None,
    }
}

/// The `net status` entry for a resolver on DoT (`net_inactive_rules`).
pub fn dns_blind_rule(dot: &ResolverDot) -> String {
    let mode = match dot.mode {
        DotMode::Yes => "DNSOverTLS=yes",
        DotMode::Opportunistic => "DNSOverTLS=opportunistic, TLS when the server offers it",
    };
    format!(
        "NN-L-NET-002/004/005/014 (DNS): blind to the local resolver's upstream — \
         systemd-resolved sends it over TLS on TCP/853 ({mode}; {}); only the queries a \
         process sends itself to UDP/53 (the 127.0.0.53 stub) are seen, not the names \
         resolved through nss-resolve, Varlink or D-Bus",
        Escaped(dot.source.display())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str, body: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, body).unwrap();
    }

    /// External audit NET-017: the drain's counts, by protocol, port and
    /// image.
    #[test]
    fn encrypted_flow_counters_count_dot_and_quic_rows() {
        let c = EncryptedFlowCounters::new();
        c.note(IPPROTO_TCP, 853, Some("/usr/lib/systemd/systemd-resolved"));
        c.note(IPPROTO_TCP, 853, Some("/usr/bin/kdig"));
        c.note(IPPROTO_TCP, 853, None);
        // `comm` is not the image: a renamed process is not the resolver.
        c.note(IPPROTO_TCP, 853, Some("/tmp/systemd-resolved.sh"));
        c.note(IPPROTO_UDP, 443, Some("/usr/bin/firefox"));
        c.note(IPPROTO_UDP, 443, None);
        // Not counted: UDP/853 (DNS over QUIC is another port's business
        // here), TCP/443 (HTTPS, DoH among it), UDP/53.
        c.note(IPPROTO_UDP, 853, None);
        c.note(IPPROTO_TCP, 443, None);
        c.note(IPPROTO_UDP, 53, None);
        assert_eq!(
            c.snapshot(),
            EncryptedFlows {
                dot: 4,
                dot_resolver: 1,
                quic: 2
            }
        );
    }

    /// The process-wide counters move with [`note_flow`].
    #[test]
    fn note_flow_feeds_the_status_counters() {
        let before = encrypted_flows();
        let ev = NetFlowEvent {
            start_ns: 1,
            end_ns: 2,
            family: 2,
            src_addr: "10.0.0.2".parse().unwrap(),
            src_port: 40_000,
            dst_addr: "1.1.1.1".parse().unwrap(),
            dst_port: 853,
            proto: IPPROTO_TCP,
            pid: 1,
            uid: 0,
            comm: "kdig".to_string(),
            exe: Some("/usr/bin/kdig".to_string()),
            proc_start_ns: 0,
            bytes_sent: 0,
            bytes_recv: 0,
            resolved_hostname: None,
            tls_fingerprint: None,
            flow_id: "abc".to_string(),
            close_reason: 0,
            phase: Default::default(),
            observed_ns: 0,
        };
        note_flow(&ev);
        let after = encrypted_flows();
        assert!(after.dot > before.dot);
    }

    /// External audit NET-017: `DNSOverTLS=` read as resolved reads it.
    #[test]
    fn resolved_conf_reader_follows_systemd_precedence() {
        let root = tempfile::tempdir().unwrap();
        let r = root.path();
        assert_eq!(resolver_dns_over_tls_under(r), None, "no resolved");

        // The shipped main file: commented defaults.
        write(
            r,
            "etc/systemd/resolved.conf",
            "[Resolve]\n#DNS=\n#DNSOverTLS=no\n",
        );
        assert_eq!(resolver_dns_over_tls_under(r), None);

        // A drop-in turns it on.
        write(
            r,
            "etc/systemd/resolved.conf.d/50-dot.conf",
            "# lab\n[Resolve]\nDNS=1.1.1.1#cloudflare-dns.com\n  DNSOverTLS = yes \n",
        );
        let dot = resolver_dns_over_tls_under(r).expect("on");
        assert_eq!(dot.mode, DotMode::Yes);
        assert!(dot
            .source
            .ends_with("etc/systemd/resolved.conf.d/50-dot.conf"));

        // A later name wins whatever its directory; an empty value resets.
        write(
            r,
            "usr/lib/systemd/resolved.conf.d/60-vendor.conf",
            "[Resolve]\nDNSOverTLS=\n",
        );
        assert_eq!(resolver_dns_over_tls_under(r), None);

        // The same name in /etc hides the vendor file.
        write(
            r,
            "etc/systemd/resolved.conf.d/60-vendor.conf",
            "[Resolve]\nDNSOverTLS=opportunistic\n",
        );
        assert_eq!(
            resolver_dns_over_tls_under(r).map(|d| d.mode),
            Some(DotMode::Opportunistic)
        );

        // A link to /dev/null in /etc masks the vendor drop-in and its
        // reset: 50-dot.conf decides again.
        let masked = r.join("etc/systemd/resolved.conf.d/60-vendor.conf");
        std::fs::remove_file(&masked).unwrap();
        std::os::unix::fs::symlink("/dev/null", &masked).unwrap();
        let dot = resolver_dns_over_tls_under(r).expect("masked reset");
        assert_eq!(dot.mode, DotMode::Yes);
        assert!(dot.source.ends_with("50-dot.conf"), "{dot:?}");

        // A file without the .conf suffix is not a drop-in.
        write(
            r,
            "etc/systemd/resolved.conf.d/70-off.conf.disabled",
            "[Resolve]\nDNSOverTLS=no\n",
        );
        assert!(resolver_dns_over_tls_under(r).is_some());
        // /run sits between /etc and /usr/lib, and sorts by name with them.
        write(
            r,
            "run/systemd/resolved.conf.d/80-runtime.conf",
            "[Resolve]\nDNSOverTLS=false\n",
        );
        assert_eq!(resolver_dns_over_tls_under(r), None);
    }

    /// The parser keeps to the `[Resolve]` section, comments, continuation
    /// lines, booleans and invalid values as systemd does.
    #[test]
    fn resolved_conf_values_parse_like_systemd() {
        let v = dns_over_tls_values(
            "DNSOverTLS=yes\n[Network]\nDNSOverTLS=yes\n[Resolve]\n; DNSOverTLS=yes\n\
             dnsovertls=yes\nDNSOverTLS=\\\n  true\nDNSOverTLS=bogus\n",
        );
        assert_eq!(v, ["true", "bogus"]);
        assert_eq!(parse_dot_mode("ON"), Some(Some(DotMode::Yes)));
        assert_eq!(parse_dot_mode("1"), Some(Some(DotMode::Yes)));
        assert_eq!(parse_dot_mode("off"), Some(None));
        assert_eq!(parse_dot_mode(""), Some(None));
        assert_eq!(
            parse_dot_mode("opportunistic"),
            Some(Some(DotMode::Opportunistic))
        );
        assert_eq!(parse_dot_mode("Opportunistic"), None);
        assert_eq!(parse_dot_mode("bogus"), None);

        // An invalid value leaves the previous one in force.
        let root = tempfile::tempdir().unwrap();
        write(
            root.path(),
            "etc/systemd/resolved.conf",
            "[Resolve]\nDNSOverTLS=yes\nDNSOverTLS=sometimes\n",
        );
        assert_eq!(
            resolver_dns_over_tls_under(root.path()).map(|d| d.mode),
            Some(DotMode::Yes)
        );
    }

    /// The main file is the first one found: /etc's (here a mask) hides
    /// /usr/lib's.
    #[test]
    fn the_first_main_file_found_is_the_only_one_read() {
        let root = tempfile::tempdir().unwrap();
        let r = root.path();
        write(
            r,
            "usr/lib/systemd/resolved.conf",
            "[Resolve]\nDNSOverTLS=yes\n",
        );
        assert!(resolver_dns_over_tls_under(r).is_some());
        std::fs::create_dir_all(r.join("etc/systemd")).unwrap();
        std::os::unix::fs::symlink("/dev/null", r.join("etc/systemd/resolved.conf")).unwrap();
        assert_eq!(resolver_dns_over_tls_under(r), None);
    }

    /// A FIFO, a directory or an oversized file never blocks or floods the
    /// status request.
    #[test]
    fn odd_files_are_skipped_or_bounded() {
        let root = tempfile::tempdir().unwrap();
        let r = root.path();
        let d = r.join("etc/systemd/resolved.conf.d");
        std::fs::create_dir_all(d.join("10-dir.conf")).unwrap();
        let fifo = std::ffi::CString::new(d.join("20-fifo.conf").as_os_str().as_bytes()).unwrap();
        // SAFETY: a NUL-terminated path in a directory of our own.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        let mut big = String::from("[Resolve]\nDNSOverTLS=yes\n");
        big.push_str(&"#".repeat(MAX_CONF_BYTES as usize));
        big.push_str("\nDNSOverTLS=no\n");
        write(r, "etc/systemd/resolved.conf.d/30-big.conf", &big);
        // The assignment past the bound is not read.
        assert_eq!(
            resolver_dns_over_tls_under(r).map(|d| d.mode),
            Some(DotMode::Yes)
        );
    }

    /// The status text names the rules, the reason and the file, escaped.
    #[test]
    fn dns_blind_rule_names_rules_reason_and_source() {
        let t = dns_blind_rule(&ResolverDot {
            mode: DotMode::Yes,
            source: PathBuf::from("/etc/systemd/resolved.conf.d/x\n.conf"),
        });
        assert!(
            t.starts_with("NN-L-NET-002/004/005/014 (DNS): blind"),
            "{t}"
        );
        assert!(t.contains("DNSOverTLS=yes"), "{t}");
        assert!(t.contains("TCP/853"), "{t}");
        assert!(!t.contains('\n'), "{t}");
        assert!(t.contains("x\\n.conf"), "{t}");
    }
}
