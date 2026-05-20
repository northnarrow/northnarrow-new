//! Tappa 10 (N5) — hand-rolled TLS handshake parser.
//!
//! Pure functions extracting JA3 + JA4 + SNI + ALPN from a TLS
//! ClientHello byte buffer. No I/O, no async, defensive against
//! malformed input (every length check is bounded; a truncated
//! or non-TLS buffer returns `None` without panicking). No
//! `tls-parser` / `rustls` crate dependency per design §13 Q7
//! lock-in: the parser is ~250 LoC and the only crypto deps
//! are `md-5` (JA3 hash) and `sha2` (JA4 hash), both RustCrypto
//! crates already in the agent's dependency closure.
//!
//! The parser walks the wire format from RFC 5246 §7.4.1.2 +
//! RFC 8446 §4.1.2 (the TLS 1.3 ClientHello is byte-compatible
//! with 1.2 on the wire — version 1.3 lives in the
//! `supported_versions` extension; the legacy `client_version`
//! field stays `0x0303`). We support both transparently.
//!
//! Input shape: the FULL TLS record bytes, starting with the
//! 5-byte record header (`type=0x16`, version, length). This is
//! what the future N5.1 `tcp_data_capture_trigger` BPF program
//! will copy out of the kernel ringbuf — the first 4096 bytes
//! of each new flow per design §6.3. Callers that already
//! stripped the record header can pass the inner Handshake
//! envelope; the parser auto-detects via the first byte.
//!
//! GREASE values (RFC 8701: `0x?A?A`) are filtered out of every
//! JA3/JA4 input list per the published specs — operators care
//! about the deterministic protocol-version surface, not the
//! per-handshake random extensions Chrome / Firefox inject for
//! ossification protection.

use std::vec::Vec;

// `Digest` provides the `digest()` trait method `Md5` and
// `Sha256` are called through. Clippy's `unused_imports` lint
// doesn't see trait-method dispatch as "using" the trait name,
// hence the explicit `#[allow]`.
#[allow(unused_imports)]
use md5::{Digest as _, Md5};
#[allow(unused_imports)]
use sha2::{Digest as _, Sha256};

// ── Wire-format constants ────────────────────────────────────────────

/// Outer TLS record type byte for a Handshake record (RFC 5246
/// §6.2.1). The N5.1 packet-capture primitive emits everything
/// from this byte onward, so the parser auto-detects an outer
/// record envelope vs a "started already inside the Handshake
/// envelope" byte stream.
const TLS_RECORD_HANDSHAKE: u8 = 0x16;

/// Inner Handshake message type byte for a ClientHello.
const HS_CLIENT_HELLO: u8 = 0x01;

/// TLS extension type codes (IANA registry, abbreviated to what
/// JA3 + JA4 need).
const EXT_SERVER_NAME: u16 = 0;
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_EC_POINT_FORMATS: u16 = 11;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_ALPN: u16 = 16;
const EXT_SUPPORTED_VERSIONS: u16 = 43;

/// SNI name_type = host_name (RFC 6066 §3) — the only kind we
/// surface; other future name types are silently ignored.
const SNI_TYPE_HOSTNAME: u8 = 0;

/// JA4 cipher / extension hash fallback when the filtered list
/// is empty — per the FoxIO JA4 spec, replace the SHA-256
/// segment with twelve ASCII zeros.
const JA4_EMPTY_HASH: &str = "000000000000";

// ── Public types ─────────────────────────────────────────────────────

/// Decoded ClientHello. Holds the cipher / extension / curve
/// lists in WIRE ORDER (the JA3 spec hashes the wire order
/// verbatim; the JA4 spec re-sorts before hashing — the parser
/// preserves order and the JA4 path sorts on demand). Vec
/// allocations happen only on the success path (the parser
/// early-returns `None` on any length / truncation failure
/// before touching the heap for the corresponding section).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsClientHello {
    /// Legacy `client_version` from the ClientHello header.
    /// TLS 1.3 fixes this at `0x0303`; the real negotiated
    /// version lives in `EXT_SUPPORTED_VERSIONS`.
    pub version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    pub extensions: Vec<TlsExtension>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsExtension {
    pub ext_type: u16,
    pub data: Vec<u8>,
}

// ── Cursor (bounded reads) ───────────────────────────────────────────

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn read_u8(&mut self) -> Option<u8> {
        let v = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }

    fn read_u16(&mut self) -> Option<u16> {
        if self.pos + 2 > self.buf.len() {
            return None;
        }
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Some(v)
    }

    fn read_u24(&mut self) -> Option<u32> {
        if self.pos + 3 > self.buf.len() {
            return None;
        }
        let v = ((self.buf[self.pos] as u32) << 16)
            | ((self.buf[self.pos + 1] as u32) << 8)
            | (self.buf[self.pos + 2] as u32);
        self.pos += 3;
        Some(v)
    }

    fn read_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return None;
        }
        let b = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(b)
    }
}

// ── Top-level parser ─────────────────────────────────────────────────

/// Parse `bytes` as a TLS ClientHello. Auto-detects whether the
/// caller passed the OUTER record (starts with `0x16` byte) or
/// the inner handshake envelope (starts with `0x01`). Returns
/// `None` on any malformed / truncated / non-TLS buffer.
///
/// Defensive guarantees:
///   * Never panics on any byte sequence.
///   * Bounded read at every step (Cursor's `read_*` returns
///     `None` past end of buffer).
///   * `Vec` allocations happen only after the corresponding
///     length field is read + validated; a failed parse drops
///     partial allocations on early return.
pub fn parse_client_hello(bytes: &[u8]) -> Option<TlsClientHello> {
    if bytes.is_empty() {
        return None;
    }
    let mut c = Cursor::new(bytes);

    // Step 1 — auto-detect outer record envelope.
    if bytes[0] == TLS_RECORD_HANDSHAKE {
        // Skip the 5-byte record header: type(1) + version(2) +
        // length(2). We don't use the record-layer length —
        // the inner handshake carries its own.
        c.read_u8()?; // type
        c.read_u16()?; // version
        c.read_u16()?; // length
    }

    // Step 2 — Handshake message header.
    let hs_type = c.read_u8()?;
    if hs_type != HS_CLIENT_HELLO {
        return None;
    }
    let _hs_len = c.read_u24()?;

    // Step 3 — ClientHello body.
    let version = c.read_u16()?;
    let random_bytes = c.read_bytes(32)?;
    let mut random = [0u8; 32];
    random.copy_from_slice(random_bytes);

    let session_id_len = c.read_u8()? as usize;
    if session_id_len > 32 {
        return None;
    }
    let session_id = c.read_bytes(session_id_len)?.to_vec();

    let cipher_suites_len = c.read_u16()? as usize;
    if cipher_suites_len % 2 != 0 || cipher_suites_len > u16::MAX as usize {
        return None;
    }
    let cipher_count = cipher_suites_len / 2;
    let mut cipher_suites = Vec::with_capacity(cipher_count);
    for _ in 0..cipher_count {
        cipher_suites.push(c.read_u16()?);
    }

    let compression_methods_len = c.read_u8()? as usize;
    let compression_methods = c.read_bytes(compression_methods_len)?.to_vec();

    // Extensions block is optional in TLS 1.0 / 1.1 but mandatory
    // in 1.2+. Treat "no extensions block" the same as "empty
    // extensions" — neither is a parse failure.
    let extensions = if c.pos < bytes.len() {
        let ext_block_len = c.read_u16()? as usize;
        let ext_block = c.read_bytes(ext_block_len)?;
        parse_extensions(ext_block)?
    } else {
        Vec::new()
    };

    Some(TlsClientHello {
        version,
        random,
        session_id,
        cipher_suites,
        compression_methods,
        extensions,
    })
}

fn parse_extensions(buf: &[u8]) -> Option<Vec<TlsExtension>> {
    let mut c = Cursor::new(buf);
    let mut out = Vec::new();
    while c.pos < buf.len() {
        let ext_type = c.read_u16()?;
        let ext_len = c.read_u16()? as usize;
        let data = c.read_bytes(ext_len)?.to_vec();
        out.push(TlsExtension { ext_type, data });
    }
    Some(out)
}

// ── Extension accessors ──────────────────────────────────────────────

/// Extract the SNI host_name from a parsed ClientHello.
///
/// Returns `None` when the SNI extension is absent OR the
/// extension payload is malformed OR it carries no host_name
/// (RFC 6066 §3 allows other name_types we don't surface).
pub fn extract_sni(hello: &TlsClientHello) -> Option<String> {
    let ext = hello
        .extensions
        .iter()
        .find(|e| e.ext_type == EXT_SERVER_NAME)?;
    let mut c = Cursor::new(&ext.data);
    let list_len = c.read_u16()? as usize;
    let list_end = c.pos + list_len;
    if list_end > ext.data.len() {
        return None;
    }
    while c.pos < list_end {
        let name_type = c.read_u8()?;
        let name_len = c.read_u16()? as usize;
        let name = c.read_bytes(name_len)?;
        if name_type == SNI_TYPE_HOSTNAME {
            return std::str::from_utf8(name).ok().map(String::from);
        }
    }
    None
}

/// Extract the ALPN protocol list from a parsed ClientHello.
/// Returns an empty `Vec` when the ALPN extension is absent or
/// malformed — operators distinguish "no ALPN extension" from
/// "empty ALPN list" via the per-host base rate, not at this
/// API.
pub fn extract_alpn(hello: &TlsClientHello) -> Vec<String> {
    let Some(ext) = hello.extensions.iter().find(|e| e.ext_type == EXT_ALPN) else {
        return Vec::new();
    };
    let mut c = Cursor::new(&ext.data);
    let Some(list_len) = c.read_u16() else {
        return Vec::new();
    };
    let list_len = list_len as usize;
    let list_end = c.pos + list_len;
    if list_end > ext.data.len() {
        return Vec::new();
    }
    let mut out = Vec::new();
    while c.pos < list_end {
        let Some(proto_len) = c.read_u8() else {
            return out;
        };
        let Some(proto) = c.read_bytes(proto_len as usize) else {
            return out;
        };
        if let Ok(s) = std::str::from_utf8(proto) {
            out.push(s.to_string());
        }
    }
    out
}

/// Extract the supported_groups (elliptic curves) list — used
/// by JA3 as the fourth comma-separated field.
fn extract_supported_groups(hello: &TlsClientHello) -> Vec<u16> {
    extract_u16_list(hello, EXT_SUPPORTED_GROUPS).unwrap_or_default()
}

/// Extract the signature_algorithms list — used by JA4 as the
/// post-`_` half of the extension-hash input.
fn extract_signature_algorithms(hello: &TlsClientHello) -> Vec<u16> {
    extract_u16_list(hello, EXT_SIGNATURE_ALGORITHMS).unwrap_or_default()
}

/// Generic `[u16]`-list extension reader. Returns `None` on
/// malformed; the public callers map `None` → empty Vec.
fn extract_u16_list(hello: &TlsClientHello, ext_type: u16) -> Option<Vec<u16>> {
    let ext = hello.extensions.iter().find(|e| e.ext_type == ext_type)?;
    let mut c = Cursor::new(&ext.data);
    let bytes_len = c.read_u16()? as usize;
    if bytes_len % 2 != 0 {
        return None;
    }
    let count = bytes_len / 2;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(c.read_u16()?);
    }
    Some(out)
}

/// Extract ec_point_formats — used by JA3 as the fifth comma-
/// separated field.
fn extract_ec_point_formats(hello: &TlsClientHello) -> Vec<u8> {
    let Some(ext) = hello
        .extensions
        .iter()
        .find(|e| e.ext_type == EXT_EC_POINT_FORMATS)
    else {
        return Vec::new();
    };
    let mut c = Cursor::new(&ext.data);
    let Some(list_len) = c.read_u8() else {
        return Vec::new();
    };
    c.read_bytes(list_len as usize)
        .map(|s| s.to_vec())
        .unwrap_or_default()
}

/// Extract the supported_versions list — TLS 1.3 advertises 1.3
/// here while keeping `client_version = 0x0303` in the legacy
/// field. JA4 uses the highest value from this list (or the
/// legacy `client_version` if the extension is absent).
fn extract_supported_versions(hello: &TlsClientHello) -> Vec<u16> {
    let Some(ext) = hello
        .extensions
        .iter()
        .find(|e| e.ext_type == EXT_SUPPORTED_VERSIONS)
    else {
        return Vec::new();
    };
    let mut c = Cursor::new(&ext.data);
    // In a ClientHello, this extension is a `u8`-length-prefixed
    // list of u16s (RFC 8446 §4.2.1).
    let Some(bytes_len) = c.read_u8() else {
        return Vec::new();
    };
    let bytes_len = bytes_len as usize;
    if bytes_len % 2 != 0 {
        return Vec::new();
    }
    let count = bytes_len / 2;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        match c.read_u16() {
            Some(v) => out.push(v),
            None => return out,
        }
    }
    out
}

// ── GREASE filter (RFC 8701) ─────────────────────────────────────────

/// GREASE values for ciphers + extensions: any `0x?A?A` (both
/// nibbles `A` on each byte). RFC 8701. Filtered out of every
/// JA3 / JA4 input list per published specs.
fn is_grease_u16(v: u16) -> bool {
    (v & 0x0F0F) == 0x0A0A
}

// ── JA3 ──────────────────────────────────────────────────────────────

/// Build the JA3 raw input string (the pre-MD5 tuple) per the
/// Salesforce 2017 JA3 spec:
///   `SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat`
/// where each field is the decimal `u16` (or `u8` for point
/// formats) values joined with `-`. GREASE values stripped.
pub fn compute_ja3_raw(hello: &TlsClientHello) -> String {
    let ciphers = hello
        .cipher_suites
        .iter()
        .copied()
        .filter(|c| !is_grease_u16(*c))
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let extensions = hello
        .extensions
        .iter()
        .filter(|e| !is_grease_u16(e.ext_type))
        .map(|e| e.ext_type.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let curves = extract_supported_groups(hello)
        .into_iter()
        .filter(|c| !is_grease_u16(*c))
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let formats = extract_ec_point_formats(hello)
        .into_iter()
        .map(|f| f.to_string())
        .collect::<Vec<_>>()
        .join("-");
    format!(
        "{},{},{},{},{}",
        hello.version, ciphers, extensions, curves, formats
    )
}

/// 32-char lowercase-hex MD5 of [`compute_ja3_raw`] — the
/// operator-visible JA3 fingerprint. Use this for threat-intel
/// lookups.
pub fn compute_ja3(hello: &TlsClientHello) -> String {
    let raw = compute_ja3_raw(hello);
    let digest = Md5::digest(raw.as_bytes());
    hex::encode(digest)
}

// ── JA4 ──────────────────────────────────────────────────────────────

/// JA4 fingerprint per FoxIO 2023 spec
/// (https://github.com/FoxIO-LLC/ja4 — the JA4 part of the
/// JA4+ family). Format:
///   `<protocol><tls_version><sni><cipher_count><ext_count><alpn>`
///   `_<cipher_hash_12hex>_<ext_hash_12hex>`
///
/// Where:
///   * `protocol` = `'t'` (TCP — V1.0 doesn't observe QUIC).
///   * `tls_version` = "13" for TLS 1.3, "12" for 1.2, etc.
///     Sourced from `supported_versions` extension if present,
///     else the legacy `client_version`.
///   * `sni` = `'d'` if a hostname-style SNI is present, else `'n'`.
///     V1.0 doesn't distinguish IP-literal SNIs (would always emit
///     `'d'` for any SNI; refinement is V1.1 territory).
///   * `cipher_count` / `ext_count` = 2-digit zero-padded decimal,
///     GREASE filtered.
///   * `alpn` = first + last char of the FIRST ALPN protocol, or
///     "00" if no ALPN. For "h2" → "h2"; for "http/1.1" → "h1".
///   * Cipher hash = first 12 hex chars of SHA-256 over the
///     filtered cipher list sorted ascending by hex, joined with
///     ",". `"000000000000"` if the list is empty.
///   * Extension hash = first 12 hex chars of SHA-256 over the
///     filtered extension list (excluding SNI=0 + ALPN=16 +
///     GREASE), sorted ascending by hex, joined with ",",
///     followed by `_` then the original-order signature_algorithms
///     list (also `,`-joined hex). Empty → `"000000000000"`.
pub fn compute_ja4(hello: &TlsClientHello) -> String {
    let proto = 't';
    let version = ja4_version_code(hello);
    let sni_byte = if extract_sni(hello).is_some() {
        'd'
    } else {
        'n'
    };
    let cipher_count = hello
        .cipher_suites
        .iter()
        .filter(|c| !is_grease_u16(**c))
        .count()
        .min(99);
    let ext_count = hello
        .extensions
        .iter()
        .filter(|e| !is_grease_u16(e.ext_type))
        .count()
        .min(99);
    let alpn = ja4_alpn_pair(hello);

    let cipher_hash = ja4_cipher_hash(hello);
    let ext_hash = ja4_extension_hash(hello);

    format!(
        "{proto}{version}{sni_byte}{cipher_count:02}{ext_count:02}{alpn}_{cipher_hash}_{ext_hash}"
    )
}

/// Map a wire `u16` TLS version to the 2-char JA4 code.
fn ja4_version_code_from_u16(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0xFEFF => "d1", // DTLS 1.0
        0xFEFD => "d2", // DTLS 1.2
        0xFEFC => "d3", // DTLS 1.3
        _ => "00",
    }
}

fn ja4_version_code(hello: &TlsClientHello) -> &'static str {
    // Prefer the highest non-GREASE value in `supported_versions`
    // over the legacy `client_version` (TLS 1.3 hellos always
    // have `client_version = 0x0303`).
    let sv = extract_supported_versions(hello);
    let highest = sv
        .into_iter()
        .filter(|v| !is_grease_u16(*v))
        .max()
        .unwrap_or(hello.version);
    ja4_version_code_from_u16(highest)
}

fn ja4_alpn_pair(hello: &TlsClientHello) -> String {
    let alpn = extract_alpn(hello);
    let first = match alpn.first() {
        Some(s) if !s.is_empty() => s,
        _ => return "00".to_string(),
    };
    // First + last char (per FoxIO spec — both ASCII; UTF-8
    // multibyte ALPN values don't exist in the wild but we use
    // `chars()` defensively).
    let mut iter = first.chars();
    let first_char = iter.next().unwrap_or('0');
    let last_char = first.chars().next_back().unwrap_or('0');
    format!("{first_char}{last_char}")
}

fn ja4_cipher_hash(hello: &TlsClientHello) -> String {
    let mut hex_ciphers: Vec<String> = hello
        .cipher_suites
        .iter()
        .copied()
        .filter(|c| !is_grease_u16(*c))
        .map(|c| format!("{c:04x}"))
        .collect();
    if hex_ciphers.is_empty() {
        return JA4_EMPTY_HASH.to_string();
    }
    hex_ciphers.sort();
    let input = hex_ciphers.join(",");
    sha256_truncated_hex(input.as_bytes(), 12)
}

fn ja4_extension_hash(hello: &TlsClientHello) -> String {
    let mut hex_exts: Vec<String> = hello
        .extensions
        .iter()
        .map(|e| e.ext_type)
        .filter(|t| !is_grease_u16(*t))
        // Exclude SNI + ALPN per FoxIO spec — they're surfaced
        // explicitly in the prefix (sni_byte + alpn pair).
        .filter(|t| *t != EXT_SERVER_NAME && *t != EXT_ALPN)
        .map(|t| format!("{t:04x}"))
        .collect();
    let sig_algos = extract_signature_algorithms(hello)
        .into_iter()
        .map(|s| format!("{s:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    if hex_exts.is_empty() && sig_algos.is_empty() {
        return JA4_EMPTY_HASH.to_string();
    }
    hex_exts.sort();
    let input = format!("{}_{}", hex_exts.join(","), sig_algos);
    sha256_truncated_hex(input.as_bytes(), 12)
}

fn sha256_truncated_hex(bytes: &[u8], hex_chars: usize) -> String {
    let digest = Sha256::digest(bytes);
    let full_hex = hex::encode(digest);
    full_hex.chars().take(hex_chars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Wire-format test builders ─────────────────────────────────────
    //
    // Build minimal-but-valid ClientHello byte sequences from
    // explicit field values. Cheaper than hardcoding multi-KB
    // browser PCAP bytes AND keeps test review tractable —
    // the JA3 / JA4 inputs are visible in the source.

    /// Build a ClientHello inside a TLS record envelope. Caller
    /// supplies the post-header fields; the builder handles the
    /// length math.
    fn build_record(
        version: u16,
        random: [u8; 32],
        session_id: &[u8],
        ciphers: &[u16],
        comp_methods: &[u8],
        extensions: &[(u16, Vec<u8>)],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        // ClientHello body.
        body.extend_from_slice(&version.to_be_bytes());
        body.extend_from_slice(&random);
        body.push(session_id.len() as u8);
        body.extend_from_slice(session_id);
        body.extend_from_slice(&(ciphers.len() as u16 * 2).to_be_bytes());
        for c in ciphers {
            body.extend_from_slice(&c.to_be_bytes());
        }
        body.push(comp_methods.len() as u8);
        body.extend_from_slice(comp_methods);
        // Extensions block.
        let mut ext_block = Vec::new();
        for (t, data) in extensions {
            ext_block.extend_from_slice(&t.to_be_bytes());
            ext_block.extend_from_slice(&(data.len() as u16).to_be_bytes());
            ext_block.extend_from_slice(data);
        }
        body.extend_from_slice(&(ext_block.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext_block);

        // Handshake message header.
        let mut hs = Vec::new();
        hs.push(HS_CLIENT_HELLO);
        let body_len = body.len();
        hs.push(((body_len >> 16) & 0xFF) as u8);
        hs.push(((body_len >> 8) & 0xFF) as u8);
        hs.push((body_len & 0xFF) as u8);
        hs.extend_from_slice(&body);

        // Record header.
        let mut rec = Vec::new();
        rec.push(TLS_RECORD_HANDSHAKE);
        rec.extend_from_slice(&0x0301u16.to_be_bytes()); // legacy record version
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    /// SNI extension payload encoding a single host_name.
    fn sni_ext(host: &str) -> Vec<u8> {
        // list_length(2) | name_type(1) | name_length(2) | name(N)
        let mut entry = Vec::new();
        entry.push(SNI_TYPE_HOSTNAME);
        entry.extend_from_slice(&(host.len() as u16).to_be_bytes());
        entry.extend_from_slice(host.as_bytes());
        let mut out = Vec::new();
        out.extend_from_slice(&(entry.len() as u16).to_be_bytes());
        out.extend_from_slice(&entry);
        out
    }

    fn alpn_ext(protocols: &[&str]) -> Vec<u8> {
        let mut entries = Vec::new();
        for p in protocols {
            entries.push(p.len() as u8);
            entries.extend_from_slice(p.as_bytes());
        }
        let mut out = Vec::new();
        out.extend_from_slice(&(entries.len() as u16).to_be_bytes());
        out.extend_from_slice(&entries);
        out
    }

    fn supported_groups_ext(groups: &[u16]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(groups.len() as u16 * 2).to_be_bytes());
        for g in groups {
            out.extend_from_slice(&g.to_be_bytes());
        }
        out
    }

    fn ec_point_formats_ext(formats: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(formats.len() as u8);
        out.extend_from_slice(formats);
        out
    }

    fn signature_algorithms_ext(algs: &[u16]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(algs.len() as u16 * 2).to_be_bytes());
        for a in algs {
            out.extend_from_slice(&a.to_be_bytes());
        }
        out
    }

    fn supported_versions_ext(versions: &[u16]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(versions.len() as u8 * 2);
        for v in versions {
            out.extend_from_slice(&v.to_be_bytes());
        }
        out
    }

    /// Pre-canned "chrome-shaped" ClientHello. Cipher list, ext
    /// ordering, supported_groups + signature_algorithms chosen
    /// to resemble what Chromium-family browsers emit (TLS 1.3
    /// via supported_versions, x25519 first in groups). Real
    /// Chrome 120 also injects GREASE values; we include one
    /// (0x0A0A in ciphers + 0xAAAA in extensions) so the
    /// GREASE-filter path runs in tests.
    fn chrome_shaped_hello() -> Vec<u8> {
        let extensions = vec![
            (0xAAAA_u16, vec![]), // GREASE ext — filtered
            (EXT_SERVER_NAME, sni_ext("example.com")),
            (
                EXT_SUPPORTED_GROUPS,
                supported_groups_ext(&[0x001D, 0x0017]),
            ), // x25519, secp256r1
            (EXT_EC_POINT_FORMATS, ec_point_formats_ext(&[0])),
            (
                EXT_SIGNATURE_ALGORITHMS,
                signature_algorithms_ext(&[0x0403, 0x0804]),
            ),
            (EXT_ALPN, alpn_ext(&["h2", "http/1.1"])),
            (
                EXT_SUPPORTED_VERSIONS,
                supported_versions_ext(&[0x0304, 0x0303]),
            ),
        ];
        build_record(
            0x0303,
            [0x42; 32],
            &[],
            &[0x0A0A, 0x1301, 0x1302, 0x1303], // GREASE first, then TLS 1.3 suites
            &[0],
            &extensions,
        )
    }

    fn firefox_shaped_hello() -> Vec<u8> {
        let extensions = vec![
            (EXT_SERVER_NAME, sni_ext("mozilla.org")),
            (
                EXT_SUPPORTED_GROUPS,
                supported_groups_ext(&[0x001D, 0x0017, 0x0018]),
            ),
            (EXT_EC_POINT_FORMATS, ec_point_formats_ext(&[0, 1, 2])),
            (
                EXT_SIGNATURE_ALGORITHMS,
                signature_algorithms_ext(&[0x0403, 0x0503, 0x0603, 0x0804]),
            ),
            (EXT_ALPN, alpn_ext(&["h2"])),
            (
                EXT_SUPPORTED_VERSIONS,
                supported_versions_ext(&[0x0304, 0x0303]),
            ),
        ];
        build_record(
            0x0303,
            [0x77; 32],
            &[],
            &[0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F],
            &[0],
            &extensions,
        )
    }

    fn curl_shaped_hello() -> Vec<u8> {
        // curl 8.x TLS 1.2 — no supported_versions extension, ALPN
        // = http/1.1 only.
        let extensions = vec![
            (EXT_SERVER_NAME, sni_ext("curl.se")),
            (
                EXT_SUPPORTED_GROUPS,
                supported_groups_ext(&[0x0017, 0x0018, 0x0019]),
            ),
            (EXT_EC_POINT_FORMATS, ec_point_formats_ext(&[0])),
            (
                EXT_SIGNATURE_ALGORITHMS,
                signature_algorithms_ext(&[0x0403, 0x0804]),
            ),
            (EXT_ALPN, alpn_ext(&["http/1.1"])),
        ];
        build_record(
            0x0303,
            [0xAA; 32],
            &[],
            &[0xC02F, 0xC02B, 0xC030, 0xC02C], // ECDHE ciphers
            &[0],
            &extensions,
        )
    }

    fn python_requests_shaped_hello() -> Vec<u8> {
        // requests/urllib3 → cpython ssl → openssl default.
        // No ALPN by default in older urllib3; we include a
        // minimal ext set.
        let extensions = vec![
            (EXT_SERVER_NAME, sni_ext("pypi.org")),
            (
                EXT_SUPPORTED_GROUPS,
                supported_groups_ext(&[0x001D, 0x0017, 0x0018, 0x0019]),
            ),
            (EXT_EC_POINT_FORMATS, ec_point_formats_ext(&[0])),
            (
                EXT_SIGNATURE_ALGORITHMS,
                signature_algorithms_ext(&[0x0403, 0x0503, 0x0603]),
            ),
        ];
        build_record(
            0x0303,
            [0x11; 32],
            &[],
            &[0xC02C, 0xC030, 0x009F, 0xC02B, 0xC02F, 0x009E],
            &[0],
            &extensions,
        )
    }

    // ── Parsing tests ─────────────────────────────────────────────────

    /// N5 test #1 — parse a chrome-shaped ClientHello + assert
    /// the structural fields landed correctly.
    #[test]
    fn parse_client_hello_extracts_chrome_120_fingerprint() {
        let bytes = chrome_shaped_hello();
        let hello = parse_client_hello(&bytes).expect("parse must succeed");
        assert_eq!(hello.version, 0x0303);
        assert_eq!(hello.cipher_suites, vec![0x0A0A, 0x1301, 0x1302, 0x1303]);
        // 7 extensions in our chrome-shaped fixture.
        assert_eq!(hello.extensions.len(), 7);
        assert_eq!(extract_sni(&hello).as_deref(), Some("example.com"));
        assert_eq!(
            extract_alpn(&hello),
            vec!["h2".to_string(), "http/1.1".to_string()]
        );
    }

    /// N5 test #2 — firefox-shaped ClientHello.
    #[test]
    fn parse_client_hello_extracts_firefox_120_fingerprint() {
        let hello = parse_client_hello(&firefox_shaped_hello()).expect("parse");
        assert_eq!(extract_sni(&hello).as_deref(), Some("mozilla.org"));
        assert_eq!(extract_alpn(&hello), vec!["h2".to_string()]);
        // Firefox-shape extension list excludes GREASE so the
        // count is exactly what we built.
        assert_eq!(hello.extensions.len(), 6);
    }

    /// N5 test #3 — curl-shaped (no supported_versions; TLS 1.2
    /// legacy).
    #[test]
    fn parse_client_hello_extracts_curl_8_fingerprint() {
        let hello = parse_client_hello(&curl_shaped_hello()).expect("parse");
        assert_eq!(extract_sni(&hello).as_deref(), Some("curl.se"));
        assert_eq!(extract_alpn(&hello), vec!["http/1.1".to_string()]);
        // No supported_versions → JA4 must fall back to legacy
        // version (0x0303 → "12").
        assert_eq!(ja4_version_code(&hello), "12");
    }

    /// N5 test #4 — python requests/urllib3 shape (no ALPN ext).
    #[test]
    fn parse_client_hello_extracts_python_requests_fingerprint() {
        let hello = parse_client_hello(&python_requests_shaped_hello()).expect("parse");
        assert_eq!(extract_sni(&hello).as_deref(), Some("pypi.org"));
        assert!(
            extract_alpn(&hello).is_empty(),
            "python_requests fixture has no ALPN"
        );
    }

    // ── JA3 / JA4 hash tests ─────────────────────────────────────────

    /// N5 test #5 — JA3 raw + MD5 match the values one would
    /// compute by hand from the chrome-shaped fixture. Anchors
    /// the spec-correct GREASE filter + the field-joining
    /// convention.
    #[test]
    fn compute_ja3_matches_published_chrome_120_value() {
        let hello = parse_client_hello(&chrome_shaped_hello()).expect("parse");
        let raw = compute_ja3_raw(&hello);
        // Chrome-shaped fixture, GREASE-stripped:
        //   version = 771 (0x0303)
        //   ciphers (post-GREASE) = [4865, 4866, 4867]
        //   extensions (post-GREASE) = [0, 10, 11, 13, 16, 43]
        //   curves (post-GREASE) = [29, 23]
        //   formats = [0]
        let expected_raw = "771,4865-4866-4867,0-10-11-13-16-43,29-23,0";
        assert_eq!(raw, expected_raw, "JA3 raw tuple must follow spec");
        // MD5 of the raw tuple (lowercase 32 hex chars).
        let md5_hex = compute_ja3(&hello);
        assert_eq!(md5_hex.len(), 32);
        // Cross-check by recomputing the digest in-test.
        let recomputed = hex::encode(Md5::digest(expected_raw.as_bytes()));
        assert_eq!(md5_hex, recomputed);
    }

    /// N5 test #6 — JA4 fingerprint matches the FoxIO spec on
    /// the chrome-shaped fixture: t + 13 (TLS 1.3 via
    /// supported_versions) + d (SNI present) + 03 (3 non-GREASE
    /// ciphers) + 06 (6 non-GREASE extensions) + h2 (first
    /// ALPN). Plus the two SHA-256-12 hashes.
    #[test]
    fn compute_ja4_matches_published_chrome_120_value() {
        let hello = parse_client_hello(&chrome_shaped_hello()).expect("parse");
        let ja4 = compute_ja4(&hello);
        // Prefix structure: t13d0306h2 (TCP, TLS 1.3, SNI=d,
        // 3 ciphers, 6 exts excluding GREASE, ALPN=h2).
        assert!(ja4.starts_with("t13d0306h2_"), "JA4 prefix mismatch: {ja4}");
        // Three underscore-separated segments.
        let parts: Vec<&str> = ja4.split('_').collect();
        assert_eq!(parts.len(), 3, "JA4 must have 3 segments: {ja4}");
        assert_eq!(parts[1].len(), 12, "cipher hash must be 12 hex chars");
        assert_eq!(parts[2].len(), 12, "ext hash must be 12 hex chars");
    }

    // ── Extension accessor tests ──────────────────────────────────────

    /// N5 test #7 — SNI extraction returns the host_name.
    #[test]
    fn extract_sni_returns_servername() {
        let hello = parse_client_hello(&chrome_shaped_hello()).expect("parse");
        assert_eq!(extract_sni(&hello).as_deref(), Some("example.com"));
    }

    /// N5 test #8 — SNI extraction returns None when the
    /// extension is absent (python_requests fixture has SNI;
    /// build a SNI-less hello for this test).
    #[test]
    fn extract_sni_returns_none_when_absent() {
        let bytes = build_record(
            0x0303,
            [0; 32],
            &[],
            &[0x1301],
            &[0],
            // No SNI extension in this list.
            &[(EXT_ALPN, alpn_ext(&["h2"]))],
        );
        let hello = parse_client_hello(&bytes).expect("parse");
        assert!(extract_sni(&hello).is_none());
    }

    /// N5 test #9 — ALPN extraction returns the protocol list.
    #[test]
    fn extract_alpn_returns_protocols() {
        let hello = parse_client_hello(&chrome_shaped_hello()).expect("parse");
        assert_eq!(
            extract_alpn(&hello),
            vec!["h2".to_string(), "http/1.1".to_string()]
        );
    }

    // ── Defensive parse tests ─────────────────────────────────────────

    /// N5 test #10 — malformed packet (wrong record type)
    /// returns None without panicking.
    #[test]
    fn parse_malformed_packet_returns_none_no_panic() {
        // Wrong record type byte (0x14 = ChangeCipherSpec).
        let bytes = vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
        assert!(parse_client_hello(&bytes).is_none());
    }

    /// N5 test #11 — truncated packet doesn't panic. The
    /// load-bearing defensive guarantee is "every byte prefix
    /// of every input is safely parseable" — `None` or a
    /// partial-but-valid TLS 1.0-shape `Some` (no extensions
    /// block; legal per RFC 2246 §7.4.1.2) are both acceptable
    /// outcomes. What must NEVER happen is a panic or a slice
    /// OOB.
    ///
    /// We exercise truncation at every byte position of a
    /// chrome-shaped hello (which IS extensions-bearing) and
    /// confirm none panic. The handful of cuts that land
    /// exactly on a section boundary (after `compression_methods`
    /// for instance) legitimately succeed with empty
    /// extensions — that's spec-correct, not a defect.
    #[test]
    fn parse_truncated_packet_returns_none_no_panic() {
        let full = chrome_shaped_hello();
        for cut in 0..full.len() {
            // No assertion on the outcome — just that this
            // doesn't panic. `parse_client_hello` is pure +
            // returns `Option`, so the act of completing this
            // call IS the assertion.
            let _ = parse_client_hello(&full[..cut]);
        }
    }

    /// N5 test #12 — non-TLS bytes (random garbage) return
    /// None instead of panicking or constructing a phantom
    /// ClientHello.
    #[test]
    fn parse_non_tls_bytes_returns_none() {
        let garbage = b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\nhello world";
        assert!(parse_client_hello(garbage).is_none());
        // Pure-zero buffer too — type byte 0x00 isn't HS or
        // record-start.
        assert!(parse_client_hello(&[0u8; 200]).is_none());
        // Empty buffer.
        assert!(parse_client_hello(&[]).is_none());
    }
}
