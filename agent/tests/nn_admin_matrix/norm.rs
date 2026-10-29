//! What the matrix normalises, and how a case is written in its golden file.
//!
//! Every value below is checked before it is replaced, so a wrong value
//! still shows as a difference:
//! - the case's directory (`<dir>`) and the repository (`<repo>`): absolute
//!   paths of this checkout and this run;
//! - the clock: a Unix time or an RFC 3339 time within ten minutes of the
//!   run (`<now>`); the fixtures' own times are older than any run;
//! - `init`'s fresh key: the private key it wrote, its public half and
//!   fingerprint (`<init-key>`, `<init-pub>`, `<init-fp>`), once the three
//!   are found to belong together;
//! - `config overlay sign`'s random nonce (`<random nonce>`) and its
//!   signatures (`<sig of key-a>`: verified over the payload with that
//!   fixture key);
//! - `policy test`'s temporary `/proc` (`nn-policy-test-<pid>-<ns>`);
//! - the host's hardening checks (`host-check`, `status`'s summary line):
//!   nn-admin's output is first compared, byte for byte, with the agent
//!   library's checks run in this process; then each check's status and
//!   value read `<status>` / `<value>`, and the warnings `<warnings>`;
//! - the mock agent's view of a request: its time (`<now>`, checked within
//!   five minutes), its nonce (`<challenge>`: the one the mock issued) and
//!   its signatures (`<sig of key-a>`, verified) — `mock.rs`.

use std::path::Path;

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use crate::fixtures;
use crate::harness::{Case, Special};

/// The slack of the clock rule, in seconds.
const NOW_SLACK: u64 = 600;

pub struct Ctx {
    replace: Vec<(String, String)>,
    started: u64,
    ended: u64,
    offline_sign: bool,
}

impl Ctx {
    pub fn new(dir: &Path, started: u64, ended: u64, case: &Case) -> Self {
        let mut replace = Vec::new();
        // init: the key it wrote, if the three belong together.
        if case.args.first().map(String::as_str) == Some("init") {
            if let Some(i) = case.args.iter().position(|a| a == "--priv-out") {
                if let Some(rel) = case.args.get(i + 1) {
                    if let Some(k) = std::fs::read_to_string(dir.join(rel))
                        .ok()
                        .and_then(|s| fixtures::parse_key_hex(s.trim()))
                    {
                        let sk = SigningKey::from_bytes(&k);
                        let vk = sk.verifying_key();
                        let fp = hex::encode(&Sha256::digest(vk.to_bytes())[..4]);
                        replace.push((hex::encode(k), "<init-key>".to_string()));
                        replace.push((hex::encode(vk.to_bytes()), "<init-pub>".to_string()));
                        replace.push((fp, "<init-fp>".to_string()));
                    }
                }
            }
        }
        for p in [dir.to_path_buf(), dir.canonicalize().unwrap_or_default()] {
            let s = p.to_string_lossy().into_owned();
            if !s.is_empty() {
                replace.push((s, "<dir>".to_string()));
            }
        }
        replace.push((env!("NN_REPO_ROOT").to_string(), "<repo>".to_string()));
        if let Ok(r) = Path::new(env!("NN_REPO_ROOT")).canonicalize() {
            replace.push((r.to_string_lossy().into_owned(), "<repo>".to_string()));
        }
        // Longest first: a path that holds another is replaced whole.
        replace.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then(a.0.cmp(&b.0)));
        replace.dedup();
        let offline_sign = case.args.starts_with(&[
            "config".to_string(),
            "overlay".to_string(),
            "sign".to_string(),
        ]);
        Ctx {
            replace,
            started,
            ended,
            offline_sign,
        }
    }

    /// `bytes` as text, normalised.
    pub fn text(&self, bytes: &[u8]) -> String {
        let mut s = escape(bytes);
        for (from, to) in &self.replace {
            if s.contains(from.as_str()) {
                s = s.replace(from.as_str(), to);
            }
        }
        s = proc_dirs(&s);
        times(
            &s,
            self.started.saturating_sub(NOW_SLACK),
            self.ended + NOW_SLACK,
        )
    }

    /// A file nn-admin wrote: an overlay signature is shown verified.
    pub fn file_text(&self, name: &str, bytes: &[u8]) -> String {
        if name.ends_with(".sig") || self.offline_sign {
            if let Some(v) = self.signature_file(bytes) {
                return self.text(v.as_bytes());
            }
        }
        self.text(bytes)
    }

    fn signature_file(&self, bytes: &[u8]) -> Option<String> {
        let mut v: serde_json::Value = serde_json::from_slice(bytes).ok()?;
        let payload: nn_proto::admin_signed_payload::SignedPayload =
            serde_json::from_value(v.get("payload")?.clone()).ok()?;
        let sigs = v.get("signatures")?.as_array()?.clone();
        let labels: Vec<serde_json::Value> = sigs
            .iter()
            .map(|s| {
                let label = s
                    .as_str()
                    .and_then(|h| hex::decode(h).ok())
                    .and_then(|b| <[u8; 64]>::try_from(b).ok())
                    .map(|sig| fixtures::signer_of(&payload, &sig))
                    .unwrap_or_else(|| "<sig: not 64 hex bytes>".to_string());
                serde_json::Value::String(label)
            })
            .collect();
        v["signatures"] = serde_json::Value::Array(labels);
        if self.offline_sign {
            v["payload"]["nonce"] = serde_json::Value::String("<random nonce>".to_string());
        }
        hex_arrays(&mut v);
        let mut s = serde_json::to_string_pretty(&v).ok()?;
        s.push('\n');
        Some(s)
    }

    /// The host's checks and `status`'s line about them.
    pub fn special(
        &self,
        case: &Case,
        stdout: &[u8],
        stderr: &[u8],
        exit: String,
    ) -> (Vec<u8>, Vec<u8>, String) {
        use northnarrow_agent::host_hardening as hh;
        if case.stdout != crate::harness::Sink::Piped {
            return (stdout.to_vec(), stderr.to_vec(), exit);
        }
        match case.special {
            Special::None => (stdout.to_vec(), stderr.to_vec(), exit),
            Special::HostChecks => {
                let checks = hh::run();
                let warns = hh::warn_count(&checks);
                let listed: Vec<serde_json::Value> = serde_json::to_value(&checks)
                    .ok()
                    .and_then(|v| v.as_array().cloned())
                    .unwrap_or_default();
                let json = case.args.iter().any(|a| a == "--json");
                let expected = if json {
                    format!("{}\n", serde_json::to_string_pretty(&checks).unwrap())
                } else {
                    hh::render_table(&checks)
                };
                if stdout != expected.as_bytes() {
                    let mut raw = b"(not the agent library's checks of this host:)\n".to_vec();
                    raw.extend_from_slice(stdout);
                    return (raw, stderr.to_vec(), exit);
                }
                let code = if warns == 0 { "0" } else { "2" };
                let exit = if exit == code {
                    "<0, or 2 with the host's warnings: checked>".to_string()
                } else {
                    exit
                };
                let out = if json {
                    // The binary's own text, its order kept: one field a line.
                    let mut t = String::new();
                    for l in expected.lines() {
                        let field = l.trim_start();
                        let indent = &l[..l.len() - field.len()];
                        if field.starts_with("\"status\": ") {
                            t.push_str(&format!("{indent}\"status\": \"<status>\",\n"));
                        } else if field.starts_with("\"value\": ") {
                            t.push_str(&format!("{indent}\"value\": \"<value>\",\n"));
                        } else {
                            t.push_str(l);
                            t.push('\n');
                        }
                    }
                    t
                } else {
                    let mut t = String::new();
                    for c in &listed {
                        t.push_str(&format!(
                            "<status>  {:<32} <value>\n",
                            c["name"].as_str().unwrap_or("")
                        ));
                    }
                    t.push_str(&format!(
                        "{} check(s), <warnings> warning(s)<, and the anti-tamper note when there are any>\n",
                        listed.len()
                    ));
                    t
                };
                (out.into_bytes(), stderr.to_vec(), exit)
            }
            Special::StatusHostLine => {
                let checks = hh::run();
                let warns = hh::warn_count(&checks);
                let line = format!(
                    "host hardening : {} check(s), {warns} warning(s){}",
                    checks.len(),
                    if warns > 0 {
                        " — see `nn-admin host-check`"
                    } else {
                        ""
                    }
                );
                let text = String::from_utf8_lossy(stdout);
                let masked = format!(
                    "host hardening : {} check(s), <the host's warnings: checked>",
                    checks.len()
                );
                let out: Vec<&str> = text.split('\n').collect();
                let out: Vec<String> = out
                    .into_iter()
                    .map(|l| {
                        if l == line {
                            masked.clone()
                        } else {
                            l.to_string()
                        }
                    })
                    .collect();
                (out.join("\n").into_bytes(), stderr.to_vec(), exit)
            }
        }
    }
}

/// Byte arrays (4, 16, 32 or 64 numbers of 0..=255: fingerprints, ids,
/// digests, nonces, signatures) as `hex:…` strings.
pub fn hex_arrays(v: &mut serde_json::Value) {
    use serde_json::Value;
    match v {
        Value::Object(map) => map.values_mut().for_each(hex_arrays),
        Value::Array(items) => {
            let bytes: Option<Vec<u8>> = items
                .iter()
                .map(|x| x.as_u64().and_then(|n| u8::try_from(n).ok()))
                .collect();
            match bytes {
                Some(b) if [4, 16, 32, 64].contains(&b.len()) => {
                    *v = Value::String(format!("hex:{}", hex::encode(b)));
                }
                _ => items.iter_mut().for_each(hex_arrays),
            }
        }
        _ => {}
    }
}

/// Text with every byte kept: invalid UTF-8 and control characters other
/// than newline and tab as `\x{..}`.
fn escape(bytes: &[u8]) -> String {
    let mut out = String::new();
    let mut rest = bytes;
    loop {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                push_escaped(&mut out, s);
                break;
            }
            Err(e) => {
                let (good, bad) = rest.split_at(e.valid_up_to());
                push_escaped(&mut out, std::str::from_utf8(good).unwrap());
                let n = e.error_len().unwrap_or(bad.len());
                for b in &bad[..n] {
                    out.push_str(&format!("\\x{{{b:02x}}}"));
                }
                rest = &bad[n..];
            }
        }
    }
    out
}

fn push_escaped(out: &mut String, s: &str) {
    for c in s.chars() {
        if c.is_control() && c != '\n' && c != '\t' {
            out.push_str(&format!("\\x{{{:02x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
}

/// `policy test`'s temporary `/proc` (`nn-policy-test-<pid>-<nanos>`).
fn proc_dirs(s: &str) -> String {
    const P: &str = "nn-policy-test-";
    if !s.contains(P) {
        return s.to_string();
    }
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find(P) {
        out.push_str(&rest[..i + P.len()]);
        let tail = &rest[i + P.len()..];
        let a = tail.bytes().take_while(u8::is_ascii_digit).count();
        let after_a = &tail[a..];
        if a > 0 && after_a.starts_with('-') {
            let b = after_a[1..].bytes().take_while(u8::is_ascii_digit).count();
            if b > 0 {
                out.push_str("<pid>-<ns>");
                rest = &after_a[1 + b..];
                continue;
            }
        }
        rest = tail;
    }
    out.push_str(rest);
    out
}

/// Unix times (ten digits) and RFC 3339 times of the run as `<now>`.
pub fn times(s: &str, lo: u64, hi: u64) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        // An RFC 3339 time: 2026-10-29T12:34:56[.ffffff]Z
        if b[i].is_ascii_digit() && (i == 0 || !b[i - 1].is_ascii_alphanumeric()) {
            if let Some(n) = rfc3339_at(&s[i..]) {
                if let Ok(t) = chrono::DateTime::parse_from_rfc3339(&s[i..i + n]) {
                    let secs = t.timestamp();
                    if secs >= 0 && (lo..=hi).contains(&(secs as u64)) {
                        out.push_str("<now>");
                        i += n;
                        continue;
                    }
                }
            }
            let d = b[i..].iter().take_while(|c| c.is_ascii_digit()).count();
            let next_alnum = b.get(i + d).is_some_and(|c| c.is_ascii_alphanumeric());
            if d == 10 && !next_alnum {
                let n: u64 = s[i..i + d].parse().unwrap();
                if (lo..=hi).contains(&n) {
                    out.push_str("<now>");
                    i += d;
                    continue;
                }
            }
            out.push_str(&s[i..i + d]);
            i += d;
            continue;
        }
        let c = s[i..].chars().next().unwrap();
        out.push(c);
        i += c.len_utf8();
    }
    out
}

/// The length of an RFC 3339 UTC time at the start of `s`, if one is there.
fn rfc3339_at(s: &str) -> Option<usize> {
    let b = s.as_bytes();
    let pat = b"dddd-dd-ddTdd:dd:dd";
    if b.len() < pat.len() {
        return None;
    }
    for (c, p) in b.iter().zip(pat.iter()) {
        let ok = match p {
            b'd' => c.is_ascii_digit(),
            _ => c == p,
        };
        if !ok {
            return None;
        }
    }
    let mut n = pat.len();
    if b.get(n) == Some(&b'.') {
        n += 1;
        n += b[n..].iter().take_while(|c| c.is_ascii_digit()).count();
    }
    if b.get(n) == Some(&b'Z') {
        Some(n + 1)
    } else if b.get(n) == Some(&b'+') && s.get(n..n + 6) == Some("+00:00") {
        Some(n + 6)
    } else {
        None
    }
}

/// A stream or a file in the golden file: each line after `| `; a last
/// line without its newline is marked.
pub fn block(text: &str) -> String {
    if text.is_empty() {
        return "(empty)\n".to_string();
    }
    let mut out = String::new();
    let ends = text.ends_with('\n');
    let body = if ends { &text[..text.len() - 1] } else { text };
    for l in body.split('\n') {
        out.push('|');
        if !l.is_empty() {
            out.push(' ');
            out.push_str(l);
        }
        out.push('\n');
    }
    if !ends {
        out.push_str("\\ no newline at the end\n");
    }
    out
}

/// The command line as a shell would read it back.
pub fn shell_words(args: &[String]) -> String {
    let mut s = String::new();
    for a in args {
        s.push(' ');
        let plain = !a.is_empty()
            && a.chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_./=:,@+%".contains(c));
        if plain {
            s.push_str(a);
        } else {
            s.push('\'');
            s.push_str(&escape(a.as_bytes()).replace('\'', "'\\''"));
            s.push('\'');
        }
    }
    s
}
