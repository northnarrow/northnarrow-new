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
//! Input shape: the bytes a capture of the flow's first client
//! data delivers, starting with the 5-byte record header
//! (`type=0x16`, version, length). This is what the future N5.1
//! `tcp_data_capture_trigger` BPF program will copy out of the
//! kernel ringbuf — the first 4096 bytes of each new flow per
//! design §6.3. Callers that already stripped the record layer
//! can pass the inner Handshake message; the parser auto-detects
//! via the first byte.
//!
//! External audit NET-018 (NN-AUD-336): the record layer may split
//! one handshake message over several records (RFC 8446 §5.1), a
//! known way to evade fingerprinting. The handshake message is
//! reassembled from consecutive handshake records by their record
//! lengths and bounded by its own length: the next record's header
//! is not read as ClientHello content, and bytes after the message
//! are not read as extensions. A buffer that ends inside the
//! message is [`ClientHelloParse::Incomplete`], distinct from
//! [`ClientHelloParse::Invalid`] (not a ClientHello), so a producer
//! can count the fingerprints it missed.
//!
//! GREASE values (RFC 8701: the sixteen `0x0A0A`, `0x1A1A`, …,
//! `0xFAFA`) are filtered out of every JA3/JA4 input list per the
//! published specs — operators care about the deterministic
//! protocol-version surface, not the per-handshake random values
//! Chrome / Firefox inject for ossification protection.
//!
//! Conformance is pinned by reference vectors (see the tests): the
//! JA4 specification's example (`technical_details/JA4.md` of
//! FoxIO-LLC/ja4, BSD 3-Clause), the JA3 README's vectors
//! (salesforce/ja3), and ClientHellos of our own whose expected JA3 and
//! JA4 come from running the reference tools on them (`python/ja3.py`
//! of salesforce/ja3, `python/ja4.py` of FoxIO-LLC/ja4).

use std::borrow::Cow;
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

/// Record header: type(1) + legacy_record_version(2) + length(2).
const RECORD_HEADER_LEN: usize = 5;

/// Major byte of every TLS / SSL 3 record version (`0x03xx`).
const TLS_RECORD_MAJOR: u8 = 0x03;

/// RFC 8446 §5.1 / RFC 5246 §6.2.1: a plaintext record fragment is at
/// most 2^14 bytes, and handshake fragments are never empty.
const MAX_RECORD_LEN: usize = 1 << 14;

/// Handshake header: msg_type(1) + length(3).
const HANDSHAKE_HEADER_LEN: usize = 4;

/// Inner Handshake message type byte for a ClientHello.
const HS_CLIENT_HELLO: u8 = 0x01;

/// RFC 8446 §4.1.2: `legacy_session_id<0..32>`.
const MAX_SESSION_ID_LEN: usize = 32;

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

/// External audit NET-014 (NN-AUD-333): the longest host name in text
/// form (RFC 1035 §2.3.4: 255 octets on the wire, 253 characters
/// without the root label and the first length octet).
const MAX_SNI_LEN: usize = 253;

/// RFC 1035 §2.3.4: a label is at most 63 octets.
const MAX_LABEL_LEN: usize = 63;

/// JA4 cipher / extension hash fallback when the filtered list
/// is empty — per the FoxIO JA4 spec, replace the SHA-256
/// segment with twelve ASCII zeros.
const JA4_EMPTY_HASH: &str = "000000000000";

// ── Public types ─────────────────────────────────────────────────────

/// Decoded ClientHello. Holds the cipher / extension / curve
/// lists in WIRE ORDER (the JA3 spec hashes the wire order
/// verbatim; the JA4 spec re-sorts before hashing — the parser
/// preserves order and the JA4 path sorts on demand). Every
/// allocation is sized by bytes the message actually holds, never
/// by a count read off the wire (external audit NET-013).
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

/// The outcome of [`parse_client_hello_outcome`] (external audit
/// NET-018, NN-AUD-336).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientHelloParse {
    /// A complete, well-formed ClientHello.
    Complete(TlsClientHello),
    /// The buffer is a well-formed beginning of a ClientHello whose
    /// message continues past it: the capture stopped before the
    /// message's end, or its next record was not delivered. Not "not
    /// TLS" — a fingerprint the producer missed.
    Incomplete,
    /// Not a ClientHello, or one that breaks the wire format.
    Invalid,
}

/// The server_name extension as JA4 and the evidence see it
/// (external audit NET-014, NN-AUD-333).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sni {
    /// No server_name extension (JA4's `i`: the client connected to an
    /// address).
    Absent,
    /// The host_name, canonical: ASCII lower case, no trailing dot,
    /// labels of 1 to 63 letters, digits or hyphens, at most 253 bytes.
    Host(String),
    /// The extension is there (JA4's `d`), but its list is malformed,
    /// holds no host_name or two of them, or the host_name is not a
    /// conforming DNS name (too long, a byte outside letters, digits,
    /// hyphen and dot, an empty or over-long label). The peer's string
    /// is not kept: this flag says that one was sent.
    NonConforming,
}

impl Sni {
    /// The canonical host name, if there is one.
    pub fn host(&self) -> Option<&str> {
        match self {
            Sni::Host(h) => Some(h),
            _ => None,
        }
    }
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

    /// Bytes left after `pos`. Every bound check is `need > remaining()`:
    /// `pos + need` could wrap for a huge `need` and pass the check (Kani,
    /// Tappa 10.8 — unreachable with today's u16/u24 lengths, but a
    /// release build wraps silently).
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
    fn read_u16(&mut self) -> Option<u16> {
        if 2 > self.remaining() {
            return None;
        }
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Some(v)
    }

    fn read_u24(&mut self) -> Option<u32> {
        if 3 > self.remaining() {
            return None;
        }
        let v = ((self.buf[self.pos] as u32) << 16)
            | ((self.buf[self.pos + 1] as u32) << 8)
            | (self.buf[self.pos + 2] as u32);
        self.pos += 3;
        Some(v)
    }

    fn read_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.remaining() {
            return None;
        }
        let b = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(b)
    }
}

/// Big-endian `u16`s of `bytes` (an even length). Sized by the bytes,
/// not by a count off the wire.
fn be_u16s(bytes: &[u8]) -> Vec<u16> {
    let (pairs, _) = bytes.as_chunks::<2>();
    pairs.iter().map(|&p| u16::from_be_bytes(p)).collect()
}

// ── Top-level parser ─────────────────────────────────────────────────

/// Parse `bytes` as a TLS ClientHello. Auto-detects whether the
/// caller passed the record layer (starts with `0x16`) or the inner
/// handshake message (starts with `0x01`). Returns `None` on any
/// malformed / truncated / non-TLS buffer; [`parse_client_hello_outcome`]
/// tells a truncated ClientHello from one that is not.
///
/// Defensive guarantees:
///   * Never panics on any byte sequence.
///   * Bounded read at every step (Cursor's `read_*` returns
///     `None` past end of buffer).
///   * Allocations are bounded by the input's length.
pub fn parse_client_hello(bytes: &[u8]) -> Option<TlsClientHello> {
    match parse_client_hello_outcome(bytes) {
        ClientHelloParse::Complete(hello) => Some(hello),
        ClientHelloParse::Incomplete | ClientHelloParse::Invalid => None,
    }
}

/// [`parse_client_hello`] with the reason when there is no ClientHello
/// (external audit NET-018, NN-AUD-336).
pub fn parse_client_hello_outcome(bytes: &[u8]) -> ClientHelloParse {
    let message = match bytes.first() {
        None => return ClientHelloParse::Incomplete,
        Some(&TLS_RECORD_HANDSHAKE) => match handshake_from_records(bytes) {
            Some(m) => m,
            None => return ClientHelloParse::Invalid,
        },
        Some(_) => Cow::Borrowed(bytes),
    };
    parse_handshake_message(&message)
}

/// The handshake message carried by the consecutive handshake records
/// at the start of `bytes`: their fragments joined, cut at the message's
/// end (`4 + length` of its header), or everything the buffer holds when
/// it ends first. `None` when the record layer is not a handshake
/// message's: a record of another type before the message ends (RFC 8446
/// §5.1 forbids interleaving), a version that is not `3.x`, an empty
/// fragment or one over 2^14 bytes. One record holding the whole message
/// is borrowed, not copied.
fn handshake_from_records(bytes: &[u8]) -> Option<Cow<'_, [u8]>> {
    let mut c = Cursor::new(bytes);
    let mut joined: Option<Vec<u8>> = None;
    let mut first: &[u8] = &[];
    loop {
        let have: &[u8] = joined.as_deref().unwrap_or(first);
        if let Some(end) = handshake_message_end(have) {
            if have.len() >= end {
                break;
            }
        }
        if c.remaining() == 0 {
            break;
        }
        if c.remaining() < RECORD_HEADER_LEN {
            // A header cut by the end of the buffer: what is there must
            // still be a handshake record's.
            let rest = &bytes[c.pos..];
            if rest[0] != TLS_RECORD_HANDSHAKE
                || rest.get(1).is_some_and(|&m| m != TLS_RECORD_MAJOR)
            {
                return None;
            }
            break;
        }
        let content_type = c.read_u8()?;
        let major = c.read_u8()?;
        let _minor = c.read_u8()?;
        let len = c.read_u16()? as usize;
        if content_type != TLS_RECORD_HANDSHAKE
            || major != TLS_RECORD_MAJOR
            || len == 0
            || len > MAX_RECORD_LEN
        {
            return None;
        }
        let fragment = c.read_bytes(len.min(c.remaining()))?;
        match joined.as_mut() {
            Some(v) => v.extend_from_slice(fragment),
            None if first.is_empty() => first = fragment,
            None => {
                let mut v = Vec::with_capacity(first.len() + fragment.len());
                v.extend_from_slice(first);
                v.extend_from_slice(fragment);
                joined = Some(v);
            }
        }
    }
    Some(match joined {
        Some(mut v) => {
            if let Some(end) = handshake_message_end(&v) {
                v.truncate(end);
            }
            Cow::Owned(v)
        }
        None => {
            let end = handshake_message_end(first).map_or(first.len(), |e| e.min(first.len()));
            Cow::Borrowed(&first[..end])
        }
    })
}

/// Where the handshake message starting `msg` ends, once its header is
/// known.
fn handshake_message_end(msg: &[u8]) -> Option<usize> {
    let header = msg.get(..HANDSHAKE_HEADER_LEN)?;
    let len = u32::from_be_bytes([0, header[1], header[2], header[3]]) as usize;
    Some(HANDSHAKE_HEADER_LEN + len)
}

/// Why the ClientHello body did not parse.
enum BodyError {
    /// A field runs past the bytes there are: a truncated message if the
    /// buffer ended inside it, malformed if the message is complete.
    Short,
    /// Malformed whatever follows.
    Bad,
}

/// Parse one handshake message (`msg` may stop short of its end).
fn parse_handshake_message(msg: &[u8]) -> ClientHelloParse {
    let mut c = Cursor::new(msg);
    match c.read_u8() {
        None => return ClientHelloParse::Incomplete,
        Some(HS_CLIENT_HELLO) => {}
        Some(_) => return ClientHelloParse::Invalid,
    }
    let Some(hs_len) = c.read_u24() else {
        return ClientHelloParse::Incomplete;
    };
    let hs_len = hs_len as usize;
    let available = c.remaining();
    let complete = available >= hs_len;
    // Bounded by the message's own length: bytes after it (the next
    // message or record, data the capture went on with) are not part of
    // the ClientHello (NET-018).
    let body = &msg[HANDSHAKE_HEADER_LEN..HANDSHAKE_HEADER_LEN + hs_len.min(available)];
    match parse_client_hello_body(body, complete) {
        Ok(hello) => ClientHelloParse::Complete(hello),
        Err(BodyError::Short) if !complete => ClientHelloParse::Incomplete,
        Err(_) => ClientHelloParse::Invalid,
    }
}

/// The ClientHello body (RFC 8446 §4.1.2), `complete` when `body` is the
/// whole of it.
fn parse_client_hello_body(body: &[u8], complete: bool) -> Result<TlsClientHello, BodyError> {
    use BodyError::{Bad, Short};
    let mut c = Cursor::new(body);
    let version = c.read_u16().ok_or(Short)?;
    let mut random = [0u8; 32];
    random.copy_from_slice(c.read_bytes(32).ok_or(Short)?);

    let session_id_len = c.read_u8().ok_or(Short)? as usize;
    if session_id_len > MAX_SESSION_ID_LEN {
        return Err(Bad);
    }
    let session_id = c.read_bytes(session_id_len).ok_or(Short)?.to_vec();

    // External audit NET-013 (NN-AUD-332) and NET-020 (2) (NN-AUD-434):
    // the length is read off the wire, so the list must fit in what the
    // message holds before anything is allocated for it. (The check was
    // `> u16::MAX`, which a `u16` never is.)
    let cipher_suites_len = c.read_u16().ok_or(Short)? as usize;
    if !cipher_suites_len.is_multiple_of(2) {
        return Err(Bad);
    }
    if cipher_suites_len > c.remaining() {
        return Err(Short);
    }
    let cipher_suites = be_u16s(c.read_bytes(cipher_suites_len).ok_or(Short)?);

    let compression_methods_len = c.read_u8().ok_or(Short)? as usize;
    let compression_methods = c.read_bytes(compression_methods_len).ok_or(Short)?.to_vec();

    // The extensions block is optional in TLS 1.0 / 1.1 but mandatory in
    // 1.2+. A message that ends after the compression methods has none;
    // when present the block runs exactly to the message's end.
    let extensions = if c.remaining() == 0 {
        if !complete {
            return Err(Short);
        }
        Vec::new()
    } else {
        let ext_block_len = c.read_u16().ok_or(Short)? as usize;
        match ext_block_len.cmp(&c.remaining()) {
            std::cmp::Ordering::Greater => return Err(Short),
            // Bytes inside the ClientHello after its extensions.
            std::cmp::Ordering::Less => return Err(Bad),
            std::cmp::Ordering::Equal => {}
        }
        parse_extensions(c.read_bytes(ext_block_len).ok_or(Short)?).ok_or(Bad)?
    };

    Ok(TlsClientHello {
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
    while c.remaining() > 0 {
        let ext_type = c.read_u16()?;
        let ext_len = c.read_u16()? as usize;
        let data = c.read_bytes(ext_len)?.to_vec();
        out.push(TlsExtension { ext_type, data });
    }
    Some(out)
}

// ── Extension accessors ──────────────────────────────────────────────

fn first_ext(hello: &TlsClientHello, ext_type: u16) -> Option<&TlsExtension> {
    hello.extensions.iter().find(|e| e.ext_type == ext_type)
}

/// The list of a `<u16 length><list>` extension body: `None` unless the
/// length matches the bytes there are.
fn u16_prefixed_list(data: &[u8]) -> Option<&[u8]> {
    let mut c = Cursor::new(data);
    let len = c.read_u16()? as usize;
    (len == c.remaining()).then(|| &data[2..])
}

/// The server_name extension (RFC 6066 §3), canonicalised (external
/// audit NET-014, NN-AUD-333). Every read stays inside the declared
/// `server_name_list`.
pub fn sni(hello: &TlsClientHello) -> Sni {
    let Some(ext) = first_ext(hello, EXT_SERVER_NAME) else {
        return Sni::Absent;
    };
    let Some(list) = u16_prefixed_list(&ext.data).filter(|l| !l.is_empty()) else {
        return Sni::NonConforming;
    };
    let mut c = Cursor::new(list);
    let mut host: Option<&[u8]> = None;
    while c.remaining() > 0 {
        let (Some(name_type), Some(name_len)) = (c.read_u8(), c.read_u16()) else {
            return Sni::NonConforming;
        };
        let Some(name) = c.read_bytes(name_len as usize) else {
            return Sni::NonConforming;
        };
        if name_type == SNI_TYPE_HOSTNAME {
            // RFC 6066: no more than one name of a type. Two host names
            // leave which one the server used open.
            if host.replace(name).is_some() {
                return Sni::NonConforming;
            }
        }
    }
    match host.and_then(canonical_host_name) {
        Some(h) => Sni::Host(h),
        None => Sni::NonConforming,
    }
}

/// Extract the SNI host_name from a parsed ClientHello, canonical
/// (see [`Sni::Host`]).
///
/// Returns `None` when the SNI extension is absent, malformed, carries
/// no host_name (RFC 6066 §3 allows other name_types we don't surface)
/// or a non-conforming one; [`sni`] tells these apart.
pub fn extract_sni(hello: &TlsClientHello) -> Option<String> {
    match sni(hello) {
        Sni::Host(h) => Some(h),
        Sni::Absent | Sni::NonConforming => None,
    }
}

/// External audit NET-014: the form a host name is compared and kept
/// in. `evil.example.com`, `EVIL.example.com` and `evil.example.com.`
/// name one host; a string of up to 65,535 bytes of the peer's choosing
/// is not one.
fn canonical_host_name(raw: &[u8]) -> Option<String> {
    let name = raw.strip_suffix(b".").unwrap_or(raw);
    if name.is_empty() || name.len() > MAX_SNI_LEN {
        return None;
    }
    let labels_ok = name.split(|&b| b == b'.').all(|label| {
        !label.is_empty()
            && label.len() <= MAX_LABEL_LEN
            && label
                .iter()
                .all(|&b| b.is_ascii_alphanumeric() || b == b'-')
    });
    labels_ok.then(|| {
        name.iter()
            .map(|b| b.to_ascii_lowercase() as char)
            .collect()
    })
}

/// The protocol names of the ALPN extension (RFC 7301 §3.1), raw, in
/// wire order. Empty when the extension is absent or malformed (every
/// read stays inside the declared list).
fn alpn_values(hello: &TlsClientHello) -> Vec<&[u8]> {
    let Some(list) = first_ext(hello, EXT_ALPN).and_then(|e| u16_prefixed_list(&e.data)) else {
        return Vec::new();
    };
    let mut c = Cursor::new(list);
    let mut out = Vec::new();
    while c.remaining() > 0 {
        let Some(name) = c.read_u8().and_then(|n| c.read_bytes(n as usize)) else {
            return Vec::new();
        };
        out.push(name);
    }
    out
}

/// Extract the ALPN protocol list from a parsed ClientHello.
/// Returns an empty `Vec` when the ALPN extension is absent or
/// malformed — operators distinguish "no ALPN extension" from
/// "empty ALPN list" via the per-host base rate, not at this
/// API. A name that is not UTF-8 is left out of this list (JA4 reads
/// the raw bytes).
pub fn extract_alpn(hello: &TlsClientHello) -> Vec<String> {
    alpn_values(hello)
        .into_iter()
        .filter_map(|p| std::str::from_utf8(p).ok().map(str::to_string))
        .collect()
}

/// Extract the supported_groups (elliptic curves) list — used
/// by JA3 as the fourth comma-separated field. Like `python/ja3.py`,
/// the last such extension counts.
fn extract_supported_groups(hello: &TlsClientHello) -> Vec<u16> {
    hello
        .extensions
        .iter()
        .rev()
        .find(|e| e.ext_type == EXT_SUPPORTED_GROUPS)
        .and_then(|e| u16_list(&e.data))
        .unwrap_or_default()
}

/// Extract the signature_algorithms list — used by JA4 as the
/// post-`_` half of the extension-hash input.
fn extract_signature_algorithms(hello: &TlsClientHello) -> Vec<u16> {
    first_ext(hello, EXT_SIGNATURE_ALGORITHMS)
        .and_then(|e| u16_list(&e.data))
        .unwrap_or_default()
}

/// A `<u16 length><u16 list>` extension body. `None` on malformed; the
/// callers map `None` → empty Vec. Sized by the bytes, not by the
/// declared length (external audit NET-013).
fn u16_list(data: &[u8]) -> Option<Vec<u16>> {
    let list = u16_prefixed_list(data)?;
    (list.len() % 2 == 0).then(|| be_u16s(list))
}

/// Extract ec_point_formats — used by JA3 as the fifth comma-
/// separated field (the last such extension, as in `python/ja3.py`).
fn extract_ec_point_formats(hello: &TlsClientHello) -> Vec<u8> {
    let Some(ext) = hello
        .extensions
        .iter()
        .rev()
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
/// legacy `client_version` if the extension is absent). Empty when
/// malformed.
fn extract_supported_versions(hello: &TlsClientHello) -> Vec<u16> {
    let Some(ext) = first_ext(hello, EXT_SUPPORTED_VERSIONS) else {
        return Vec::new();
    };
    // In a ClientHello, this extension is a `u8`-length-prefixed
    // list of u16s (RFC 8446 §4.2.1).
    let mut c = Cursor::new(&ext.data);
    let Some(bytes_len) = c.read_u8() else {
        return Vec::new();
    };
    let bytes_len = bytes_len as usize;
    if !bytes_len.is_multiple_of(2) || bytes_len != c.remaining() {
        return Vec::new();
    }
    be_u16s(&ext.data[1..])
}

// ── GREASE filter (RFC 8701) ─────────────────────────────────────────

/// GREASE values (RFC 8701 §2): the sixteen `0x0A0A`, `0x1A1A`, …,
/// `0xFAFA` — both bytes equal, low nibble `A`. Filtered out of every
/// JA3 / JA4 input list per published specs.
///
/// External audit NET-007 (NN-AUD-330): the test was
/// `(v & 0x0F0F) == 0x0A0A`, which also accepts the 240 values with
/// two different bytes (`0x1A2A`, `0x3AFA`, …). They are not GREASE,
/// the reference implementations keep them, and a client that sent one
/// got a fingerprint no feed has.
fn is_grease_u16(v: u16) -> bool {
    let [hi, lo] = v.to_be_bytes();
    hi == lo && (lo & 0x0F) == 0x0A
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

/// JA4 fingerprint per the FoxIO specification
/// (https://github.com/FoxIO-LLC/ja4, `technical_details/JA4.md`; the
/// JA4 part of JA4+, BSD 3-Clause). Format:
///   `<protocol><tls_version><sni><cipher_count><ext_count><alpn>`
///   `_<cipher_hash_12hex>_<ext_hash_12hex>`
///
/// Where:
///   * `protocol` = `'t'` (TCP — V1.0 doesn't observe QUIC).
///   * `tls_version` = "13" for TLS 1.3, "12" for 1.2, …, "s3", "s2";
///     the highest non-GREASE value of `supported_versions` when the
///     extension is there ("00" when it holds none), else the legacy
///     `client_version`. Unknown = "00".
///   * `sni` = `'d'` when the server_name extension is present, `'i'`
///     when it is not (external audit NET-008: it was `'n'`, a value
///     the specification does not have).
///   * `cipher_count` / `ext_count` = 2-digit zero-padded decimal,
///     GREASE filtered, at most 99; the extensions include SNI and
///     ALPN.
///   * `alpn` = first + last character of the FIRST ALPN protocol
///     name, "00" when there is none or it is empty; a byte outside
///     ASCII is `'9'`, as the reference implementations print it
///     (`first_last` in `rust/ja4/src/tls.rs`, `first_last_alpn` in
///     `python/ja4.py`). "h2" → "h2", "http/1.1" → "h1".
///   * Cipher hash = first 12 hex chars of SHA-256 over the
///     filtered cipher list sorted ascending by hex, joined with
///     ",". `"000000000000"` if the list is empty.
///   * Extension hash = first 12 hex chars of SHA-256 over the
///     filtered extension list (excluding SNI=0 + ALPN=16 +
///     GREASE), sorted ascending by hex, joined with ",",
///     followed by `_` then the original-order signature_algorithms
///     list (GREASE filtered, `,`-joined hex). Without signature
///     algorithms the `_` is left out (external audit NET-008).
///     Empty → `"000000000000"`.
pub fn compute_ja4(hello: &TlsClientHello) -> String {
    let proto = 't';
    let version = ja4_version_code(hello);
    let sni_byte = if first_ext(hello, EXT_SERVER_NAME).is_some() {
        'd'
    } else {
        'i'
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

/// Map a wire `u16` TLS version to the 2-char JA4 code (the table of
/// the specification and of both reference implementations; a TCP
/// ClientHello has no DTLS version).
fn ja4_version_code_from_u16(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0002 => "s2",
        _ => "00",
    }
}

fn ja4_version_code(hello: &TlsClientHello) -> &'static str {
    // Prefer the highest non-GREASE value in `supported_versions`
    // over the legacy `client_version` (TLS 1.3 hellos always
    // have `client_version = 0x0303`). With the extension present the
    // version is its value, whatever the legacy field says.
    if first_ext(hello, EXT_SUPPORTED_VERSIONS).is_none() {
        return ja4_version_code_from_u16(hello.version);
    }
    extract_supported_versions(hello)
        .into_iter()
        .filter(|v| !is_grease_u16(*v))
        .max()
        .map_or("00", ja4_version_code_from_u16)
}

fn ja4_alpn_pair(hello: &TlsClientHello) -> String {
    let values = alpn_values(hello);
    let Some((&first, &last)) = values.first().and_then(|v| Some((v.first()?, v.last()?))) else {
        return "00".to_string();
    };
    // Each end as the reference implementations print it: an ASCII byte
    // is itself, any other byte '9'. (The specification's text asks for
    // the hex form of a non-alphanumeric value; both implementations
    // print '9', and the feeds come from them.)
    let shown = |b: u8| if b.is_ascii() { b as char } else { '9' };
    format!("{}{}", shown(first), shown(last))
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
        .filter(|s| !is_grease_u16(*s))
        .map(|s| format!("{s:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    hex_exts.sort();
    let exts = hex_exts.join(",");
    // External audit NET-008 (NN-AUD-331), checked against the
    // specification's vector: "If there are no signature algorithms in
    // the hello packet, then the string ends without an underscore".
    let input = if sig_algos.is_empty() {
        exts
    } else {
        format!("{exts}_{sig_algos}")
    };
    if input.is_empty() {
        return JA4_EMPTY_HASH.to_string();
    }
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

    /// The ClientHello handshake message (header + body); `extensions`
    /// `None` leaves the extensions block out (TLS 1.0 / 1.1).
    fn build_handshake(
        version: u16,
        random: [u8; 32],
        session_id: &[u8],
        ciphers: &[u16],
        comp_methods: &[u8],
        extensions: Option<&[(u16, Vec<u8>)]>,
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
        if let Some(extensions) = extensions {
            let mut ext_block = Vec::new();
            for (t, data) in extensions {
                ext_block.extend_from_slice(&t.to_be_bytes());
                ext_block.extend_from_slice(&(data.len() as u16).to_be_bytes());
                ext_block.extend_from_slice(data);
            }
            body.extend_from_slice(&(ext_block.len() as u16).to_be_bytes());
            body.extend_from_slice(&ext_block);
        }

        // Handshake message header.
        let mut hs = Vec::new();
        hs.push(HS_CLIENT_HELLO);
        let body_len = body.len();
        hs.push(((body_len >> 16) & 0xFF) as u8);
        hs.push(((body_len >> 8) & 0xFF) as u8);
        hs.push((body_len & 0xFF) as u8);
        hs.extend_from_slice(&body);
        hs
    }

    /// One handshake record carrying `payload`.
    fn record(payload: &[u8]) -> Vec<u8> {
        let mut rec = Vec::new();
        rec.push(TLS_RECORD_HANDSHAKE);
        rec.extend_from_slice(&0x0301u16.to_be_bytes()); // legacy record version
        rec.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        rec.extend_from_slice(payload);
        rec
    }

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
        record(&build_handshake(
            version,
            random,
            session_id,
            ciphers,
            comp_methods,
            Some(extensions),
        ))
    }

    /// The handshake message of a single-record ClientHello, split into
    /// records at `cuts` (offsets into the message).
    fn refragment(single_record: &[u8], cuts: &[usize]) -> Vec<u8> {
        let hs = &single_record[RECORD_HEADER_LEN..];
        let mut out = Vec::new();
        let mut start = 0;
        for &cut in cuts.iter().chain(std::iter::once(&hs.len())) {
            out.extend_from_slice(&record(&hs[start..cut]));
            start = cut;
        }
        out
    }

    /// SNI extension payload encoding a single host_name.
    fn sni_ext(host: &str) -> Vec<u8> {
        sni_ext_bytes(host.as_bytes())
    }

    fn sni_ext_bytes(host: &[u8]) -> Vec<u8> {
        // list_length(2) | name_type(1) | name_length(2) | name(N)
        let mut entry = Vec::new();
        entry.push(SNI_TYPE_HOSTNAME);
        entry.extend_from_slice(&(host.len() as u16).to_be_bytes());
        entry.extend_from_slice(host);
        let mut out = Vec::new();
        out.extend_from_slice(&(entry.len() as u16).to_be_bytes());
        out.extend_from_slice(&entry);
        out
    }

    fn alpn_ext(protocols: &[&str]) -> Vec<u8> {
        alpn_ext_bytes(&protocols.iter().map(|p| p.as_bytes()).collect::<Vec<_>>())
    }

    fn alpn_ext_bytes(protocols: &[&[u8]]) -> Vec<u8> {
        let mut entries = Vec::new();
        for p in protocols {
            entries.push(p.len() as u8);
            entries.extend_from_slice(p);
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

    // ── Reference vectors ─────────────────────────────────────────────
    //
    // ClientHellos of our own, built below from explicit fields: a
    // Firefox-like TLS 1.3 hello (with and without SNI), a TLS 1.2 hello
    // with ALPN h2, Chrome-like hellos with GREASE everywhere, with GREASE
    // in signature_algorithms and with a first ALPN name outside ASCII,
    // values shaped like GREASE that are not, repeated curve extensions, a
    // hello without SNI or cipher, and the two JA3 README hellos. The
    // expected values were not computed by this code: the reference tools
    // were run locally on these exact bytes (each vector's SHA-256 is
    // pinned), in a pcap holding a TCP handshake to port 443 and the
    // ClientHello:
    //   * JA3 — salesforce/ja3 `python/ja3.py` at commit
    //     502cc6395811c54743b0561419d61900a6df3ff7, dpkt 1.9.8;
    //   * JA4 — FoxIO-LLC/ja4 `python/ja4.py` (JA4: TLS Client
    //     Fingerprinting, BSD 3-Clause) at commit
    //     c6469a7b0dbf8fe963810162429fbfd9d1acc4d5, with tshark 4.2.2
    //     (Ubuntu 24.04 package 4.2.2-1.1build3).
    // Neither tool's code nor data is in this repository; the generator
    // (the same fields in Python) and the commands are kept with the lab
    // notes of this change (lab PR 202).

    struct Vector {
        name: &'static str,
        build: fn() -> Vec<u8>,
        sha256: &'static str,
        ja3_raw: &'static str,
        ja3: &'static str,
        ja4: &'static str,
    }

    const STATUS_REQUEST: [u8; 5] = [1, 0, 0, 0, 0];

    fn key_share_ext(shares: &[(u16, &[u8])]) -> Vec<u8> {
        let mut entries = Vec::new();
        for (group, key) in shares {
            entries.extend_from_slice(&group.to_be_bytes());
            entries.extend_from_slice(&(key.len() as u16).to_be_bytes());
            entries.extend_from_slice(key);
        }
        let mut out = (entries.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(&entries);
        out
    }

    fn bytes_from(start: u8, len: u8) -> Vec<u8> {
        (start..start + len).collect()
    }

    fn tls13_h2_with(with_sni: bool) -> Vec<u8> {
        let key = bytes_from(0x40, 32);
        let mut extensions = vec![
            (EXT_SERVER_NAME, sni_ext("www.example.com")),
            (0x0017, vec![]),
            (0xff01, vec![0]),
            (
                EXT_SUPPORTED_GROUPS,
                supported_groups_ext(&[0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101]),
            ),
            (EXT_EC_POINT_FORMATS, ec_point_formats_ext(&[0])),
            (0x0023, vec![]),
            (EXT_ALPN, alpn_ext(&["h2", "http/1.1"])),
            (0x0005, STATUS_REQUEST.to_vec()),
            (
                0x0022,
                signature_algorithms_ext(&[0x0403, 0x0503, 0x0603, 0x0203]),
            ),
            (0x0033, key_share_ext(&[(0x001d, &key)])),
            (
                EXT_SUPPORTED_VERSIONS,
                supported_versions_ext(&[0x0304, 0x0303]),
            ),
            (
                EXT_SIGNATURE_ALGORITHMS,
                signature_algorithms_ext(&[
                    0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203,
                    0x0201,
                ]),
            ),
            (0x002d, vec![1, 1]),
            (0x001c, vec![0x40, 0x01]),
            (0x0015, vec![0; 40]),
        ];
        if !with_sni {
            extensions.remove(0);
        }
        let random: [u8; 32] = bytes_from(0, 32).try_into().expect("32 bytes");
        build_record(
            0x0303,
            random,
            &bytes_from(0x20, 32),
            &[
                0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a,
                0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            &[0],
            &extensions,
        )
    }

    fn tls13_h2() -> Vec<u8> {
        tls13_h2_with(true)
    }

    fn tls13_no_sni() -> Vec<u8> {
        tls13_h2_with(false)
    }

    /// TLS 1.2 (no supported_versions), ALPN h2, SCSV; `0xEFEF`,
    /// `0xEEEE`, `0xEDED` in signature_algorithms are not GREASE.
    fn tls12_h2() -> Vec<u8> {
        build_record(
            0x0303,
            [0x11; 32],
            &[],
            &[
                0xc030, 0xc02c, 0xc028, 0xc024, 0xc014, 0xc00a, 0x009f, 0x006b, 0x0039, 0xcca9,
                0xcca8, 0xccaa, 0xff85, 0x00c4, 0x0088, 0x0081, 0x009d, 0x003d, 0x0035, 0x00c0,
                0xc02f, 0xc02b, 0xc027, 0xc023, 0xc013, 0xc009, 0x009e, 0x0067, 0x0033, 0x009c,
                0x003c, 0x002f, 0x0005, 0x0004, 0x000a, 0x00ff,
            ],
            &[0],
            &[
                (EXT_SERVER_NAME, sni_ext("tls12.example.net")),
                (EXT_EC_POINT_FORMATS, ec_point_formats_ext(&[0, 1, 2])),
                (
                    EXT_SUPPORTED_GROUPS,
                    supported_groups_ext(&[0x001d, 0x0017, 0x0018]),
                ),
                (
                    EXT_SIGNATURE_ALGORITHMS,
                    signature_algorithms_ext(&[
                        0x0601, 0x0603, 0xefef, 0x0501, 0x0503, 0x0401, 0x0403, 0xeeee, 0xeded,
                        0x0301, 0x0303, 0x0201, 0x0203,
                    ]),
                ),
                (EXT_ALPN, alpn_ext(&["h2", "http/1.1"])),
            ],
        )
    }

    const CHROME_SIGALGS: [u16; 8] = [
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ];

    /// Chrome-like: GREASE in ciphers, extensions, groups, key_share and
    /// supported_versions.
    fn chrome_like(host: &str, alpn: &[&[u8]], sig_algs: &[u16], fill: u8, alps: bool) -> Vec<u8> {
        let key = bytes_from(0x60, 32);
        let mut extensions = vec![
            (0x4a4a, vec![]),
            (EXT_SERVER_NAME, sni_ext(host)),
            (0x0017, vec![]),
            (0xff01, vec![0]),
            (
                EXT_SUPPORTED_GROUPS,
                supported_groups_ext(&[0xcaca, 0x11ec, 0x001d, 0x0017, 0x0018]),
            ),
            (EXT_EC_POINT_FORMATS, ec_point_formats_ext(&[0])),
            (0x0023, vec![]),
            (EXT_ALPN, alpn_ext_bytes(alpn)),
            (0x0005, STATUS_REQUEST.to_vec()),
            (EXT_SIGNATURE_ALGORITHMS, signature_algorithms_ext(sig_algs)),
            (0x0012, vec![]),
            (0x0033, key_share_ext(&[(0xcaca, &[0]), (0x001d, &key)])),
            (0x002d, vec![1, 1]),
            (
                EXT_SUPPORTED_VERSIONS,
                supported_versions_ext(&[0x2a2a, 0x0304, 0x0303]),
            ),
            (0x001b, vec![2, 0, 2]),
        ];
        if alps {
            extensions.push((0x4469, alpn_ext(&["h2"])));
        }
        extensions.push((0x7a7a, vec![0]));
        extensions.push((0x0015, vec![0; 30]));
        build_record(
            0x0303,
            [fill; 32],
            &[fill ^ 0xff; 32],
            &[
                0xaaaa, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
                0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
            ],
            &[0],
            &extensions,
        )
    }

    fn grease_everywhere() -> Vec<u8> {
        chrome_like(
            "grease.example.org",
            &[b"h2", b"http/1.1"],
            &CHROME_SIGALGS,
            0x22,
            false,
        )
    }

    fn sigalg_grease() -> Vec<u8> {
        let mut algs = vec![0x0a0a];
        algs.extend_from_slice(&CHROME_SIGALGS);
        chrome_like(
            "sigalg.example.org",
            &[b"h2", b"http/1.1"],
            &algs,
            0x44,
            true,
        )
    }

    fn non_ascii_alpn() -> Vec<u8> {
        chrome_like(
            "alpn.example.org",
            &[&[0xba, 0xad], b"http/1.1"],
            &CHROME_SIGALGS,
            0x55,
            false,
        )
    }

    /// External audit NET-007: `0x1A2A` and `0x3AFA` have the `0x?A?A`
    /// shape but two different bytes; `0x0A0A` and `0x2A2A` are GREASE.
    fn grease_shaped() -> Vec<u8> {
        build_record(
            0x0303,
            [0; 32],
            &[],
            &[0x0A0A, 0x1A2A, 0x1301, 0x3AFA],
            &[0],
            &[
                (0x0A0A, vec![]),
                (0x3AFA, vec![]),
                (
                    EXT_SUPPORTED_GROUPS,
                    supported_groups_ext(&[0x2A2A, 0x1A2A, 0x001D]),
                ),
                (EXT_EC_POINT_FORMATS, ec_point_formats_ext(&[0])),
            ],
        )
    }

    fn repeated_curves() -> Vec<u8> {
        build_record(
            0x0303,
            [0; 32],
            &[],
            &[0x1301],
            &[0],
            &[
                (EXT_SUPPORTED_GROUPS, supported_groups_ext(&[23])),
                (EXT_EC_POINT_FORMATS, ec_point_formats_ext(&[1])),
                (EXT_SUPPORTED_GROUPS, supported_groups_ext(&[29, 24])),
                (EXT_EC_POINT_FORMATS, ec_point_formats_ext(&[0])),
            ],
        )
    }

    /// No server_name, no cipher, TLS 1.3 by the legacy field, one
    /// extension (quic_transport_parameters, empty).
    fn no_sni_no_cipher() -> Vec<u8> {
        record(&build_handshake(
            0x0304,
            [0; 32],
            &[],
            &[],
            &[0],
            Some(&[(0x0039, vec![])]),
        ))
    }

    /// The lists of the JA3 README's first vector.
    fn ja3_readme_1() -> Vec<u8> {
        build_record(
            0x0301,
            [0; 32],
            &[],
            &[47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4],
            &[0],
            &[
                (EXT_SERVER_NAME, sni_ext("example.com")),
                (EXT_SUPPORTED_GROUPS, supported_groups_ext(&[23, 24, 25])),
                (EXT_EC_POINT_FORMATS, ec_point_formats_ext(&[0])),
            ],
        )
    }

    /// The JA3 README's second vector: no extensions block at all.
    fn ja3_readme_2() -> Vec<u8> {
        record(&build_handshake(
            0x0301,
            [0; 32],
            &[],
            &[4, 5, 10, 9, 100, 98, 3, 6, 19, 18, 99],
            &[0],
            None,
        ))
    }

    const VECTORS: &[Vector] = &[
        Vector {
            name: "tls13-h2",
            build: tls13_h2,
            sha256: "4ffd4dd30d6a2b04d3d4d67ec80f6c792cb25b5e3f1349bd7652bc9398ad85c6",
            ja3_raw: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-\
                      49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-21,\
                      29-23-24-25-256-257,0",
            ja3: "579ccef312d18482fc42e2b822ca2430",
            ja4: "t13d1715h2_5b57614c22b0_3d5424432f57",
        },
        Vector {
            name: "tls13-no-sni",
            build: tls13_no_sni,
            sha256: "2e089b278affd1728fea137dac7f2d1805c8937ed8129a25595ae4292f4b6b59",
            ja3_raw: "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-\
                      49172-156-157-47-53,23-65281-10-11-35-16-5-34-51-43-13-45-28-21,\
                      29-23-24-25-256-257,0",
            ja3: "b8419f4529b976b01d86fb910efac57f",
            ja4: "t13i1714h2_5b57614c22b0_3d5424432f57",
        },
        Vector {
            name: "tls12-h2",
            build: tls12_h2,
            sha256: "8abca3690c6e8357d592fe19455f1667cec366defde764b2523387eb6da939de",
            ja3_raw: "771,49200-49196-49192-49188-49172-49162-159-107-57-52393-52392-52394-\
                      65413-196-136-129-157-61-53-192-49199-49195-49191-49187-49171-49161-158-\
                      103-51-156-60-47-5-4-10-255,0-11-10-13-16,29-23-24,0-1-2",
            ja3: "6363a611ad267aab336c060537de8a01",
            ja4: "t12d3605h2_5162a911b73a_aaf95bb78ec9",
        },
        Vector {
            name: "grease-everywhere",
            build: grease_everywhere,
            sha256: "e693860a2a401f90ba985e06e825b243472e5126b1ed6173726b0ee0918b5c16",
            ja3_raw: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-\
                      157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,4588-29-23-24,0",
            ja3: "e828d63cec85b5bf361358eeb805330a",
            ja4: "t13d1515h2_8daaf6152771_de4a06bb82e3",
        },
        Vector {
            name: "sigalg-grease",
            build: sigalg_grease,
            sha256: "89a97da9a8ca3a9c0922c43a8f3443879e3d9c7276f793332592f1aa5ea7e37c",
            ja3_raw: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-\
                      157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,\
                      4588-29-23-24,0",
            ja3: "9dc1248ecb4f046e22cec6b3d75d0618",
            ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1",
        },
        Vector {
            name: "non-ascii-alpn",
            build: non_ascii_alpn,
            sha256: "eeaa01db6ae23c5649cfc14b222152bc9e53806d6df758df799f06e0a3c6a743",
            ja3_raw: "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-\
                      157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,4588-29-23-24,0",
            ja3: "e828d63cec85b5bf361358eeb805330a",
            ja4: "t13d151599_8daaf6152771_de4a06bb82e3",
        },
        Vector {
            name: "grease-shaped",
            build: grease_shaped,
            sha256: "4ee8c09387ca12262a279c339777579f9d15bdbafe8ff4ebb2adb86217b7f20a",
            ja3_raw: "771,6698-4865-15098,15098-10-11,6698-29,0",
            ja3: "a3d81bc03d4ba06f1174f482f8e41a48",
            ja4: "t12i030300_83c40b11d8d2_3ed318914742",
        },
        Vector {
            name: "repeated-curves",
            build: repeated_curves,
            sha256: "79f7c3a0b1a723e292a73879433a9d72b406b3a4a6788c4cab985337cc407373",
            ja3_raw: "771,4865,10-11-10-11,29-24,0",
            ja3: "ab7326fb2d6e0c3cfe8ba3782e68a9a0",
            ja4: "t12i010400_0f2cb44170f4_dba5e3e173c7",
        },
        Vector {
            name: "no-sni-no-cipher",
            build: no_sni_no_cipher,
            sha256: "3b4253bb26baba76aaa4214adc8e91d9ca9d49890c0d18ab6a8163ab24259781",
            ja3_raw: "772,,57,,",
            ja3: "b6d6d90fe2d0939e11dc6027b63d5139",
            ja4: "t13i000100_000000000000_2cfe23c976cf",
        },
        Vector {
            name: "ja3-readme-1",
            build: ja3_readme_1,
            sha256: "10d92b03f2abd70c104fccc0b0c47532d36464200f6289f4bee5dd557f6d4fbe",
            ja3_raw: "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0",
            ja3: "ada70206e40642a3e4461f35503241d5",
            ja4: "t10d120300_d94e65cdb899_33a13ba74d1c",
        },
        Vector {
            name: "ja3-readme-2",
            build: ja3_readme_2,
            sha256: "9377e4f44ca22aaa17b893fff0757153b83021b2406fe0c06b5e52b33bc7d71f",
            ja3_raw: "769,4-5-10-9-100-98-3-6-19-18-99,,,",
            ja3: "de350869b8c85de67a350c8d186f11e6",
            ja4: "t10i110000_3609b414f052_000000000000",
        },
    ];

    fn vector(name: &str) -> Vec<u8> {
        let v = VECTORS.iter().find(|v| v.name == name).expect(name);
        (v.build)()
    }

    /// The JA4 specification's example (`technical_details/JA4.md`,
    /// "Example" and "Raw Output", FoxIO-LLC/ja4 at commit c6469a7; JA4:
    /// TLS Client Fingerprinting is BSD 3-Clause, `LICENSE-JA4` there): the
    /// ciphers, extensions and signature algorithms of its `JA4_ro` in
    /// wire order, TLS 1.3 by supported_versions, SNI, ALPN `h2`. GREASE
    /// values, which the specification says to ignore anywhere, are added
    /// in every list when `grease` is set.
    fn ja4_spec_example(signature_algorithms: &[u16], grease: bool) -> Vec<u8> {
        let mut ciphers = vec![
            0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ];
        let mut versions = vec![0x0304, 0x0303];
        let mut algs = signature_algorithms.to_vec();
        if grease {
            ciphers.insert(0, 0x0A0A);
            versions.insert(0, 0x3A3A);
            algs.insert(0, 0x2A2A);
        }
        let mut extensions: Vec<(u16, Vec<u8>)> = [
            0x001b, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002d, 0x000d, 0x0005, 0x0023, 0x0012,
            0x002b, 0xff01, 0x000b, 0x000a, 0x0015,
        ]
        .into_iter()
        .map(|t| {
            let data = match t {
                EXT_SERVER_NAME => sni_ext("example.com"),
                EXT_ALPN => alpn_ext(&["h2"]),
                EXT_SIGNATURE_ALGORITHMS => signature_algorithms_ext(&algs),
                EXT_SUPPORTED_VERSIONS => supported_versions_ext(&versions),
                _ => Vec::new(),
            };
            (t, data)
        })
        .collect();
        if grease {
            extensions.insert(0, (0x1A1A, Vec::new()));
            extensions.push((0xFAFA, vec![0]));
        }
        build_record(0x0303, [0x5A; 32], &[0x01; 32], &ciphers, &[0], &extensions)
    }

    const JA4_SPEC_SIGNATURE_ALGORITHMS: [u16; 8] = [
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ];

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

    /// External audit NET-007 (NN-AUD-330): exactly the sixteen values of
    /// RFC 8701 §2 are GREASE.
    #[test]
    fn grease_filter_matches_rfc8701_exactly() {
        let grease: Vec<u16> = (0..=0x0Fu16)
            .map(|n| (n << 12) | 0x0A00 | (n << 4) | 0x0A)
            .collect();
        assert_eq!(grease.len(), 16);
        assert_eq!((grease[0], grease[15]), (0x0A0A, 0xFAFA));
        for g in &grease {
            assert!(is_grease_u16(*g), "{g:#06x}");
        }
        // The 0x?A?A shape with two different bytes is not GREASE.
        for v in [0x1A2Au16, 0x3AFA, 0xFA0A, 0x0AFA] {
            assert!(!is_grease_u16(v), "{v:#06x}");
        }
        let all = (0..=u16::MAX).filter(|v| is_grease_u16(*v)).count();
        assert_eq!(all, 16);
        for v in [0x1301u16, 0xC02F, 0x00AA, 0xFF01, 0xEEEE, 0x0A0B] {
            assert!(!is_grease_u16(v), "{v:#06x}");
        }
    }

    /// External audit NET-007: a value shaped like GREASE that is not one
    /// stays in the JA3 and JA4 lists, as in the reference tools (values in
    /// the `grease-shaped` vector).
    #[test]
    fn ja3_keeps_values_shaped_like_grease_that_are_not() {
        let hello = parse_client_hello(&grease_shaped()).expect("parse");
        assert_eq!(
            compute_ja3_raw(&hello),
            "771,6698-4865-15098,15098-10-11,6698-29,0"
        );
        assert_eq!(compute_ja3(&hello), "a3d81bc03d4ba06f1174f482f8e41a48");
        assert_eq!(compute_ja4(&hello), "t12i030300_83c40b11d8d2_3ed318914742");
    }

    /// The two JA3 strings and hashes of the JA3 README (salesforce/ja3,
    /// `README.md`, "How it works", at 502cc63, BSD 3-Clause), on
    /// ClientHellos carrying those lists; the second has no extensions
    /// block at all.
    #[test]
    fn ja3_matches_the_salesforce_readme_vectors() {
        let hello = parse_client_hello(&ja3_readme_1()).expect("parse");
        assert_eq!(
            compute_ja3_raw(&hello),
            "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
        );
        assert_eq!(compute_ja3(&hello), "ada70206e40642a3e4461f35503241d5");

        let hello = parse_client_hello(&ja3_readme_2()).expect("parse");
        assert_eq!(
            compute_ja3_raw(&hello),
            "769,4-5-10-9-100-98-3-6-19-18-99,,,"
        );
        assert_eq!(compute_ja3(&hello), "de350869b8c85de67a350c8d186f11e6");
    }

    /// The vectors are the bytes the reference tools read: a change to a
    /// builder above invalidates its expected values.
    #[test]
    fn reference_vectors_are_the_bytes_the_tools_read() {
        for v in VECTORS {
            let digest = hex::encode(Sha256::digest((v.build)()));
            assert_eq!(digest, v.sha256, "{}", v.name);
        }
    }

    /// JA3 of every vector equals `python/ja3.py`'s.
    #[test]
    fn ja3_matches_the_reference_on_our_client_hellos() {
        for v in VECTORS {
            let hello = parse_client_hello(&(v.build)()).expect(v.name);
            assert_eq!(compute_ja3_raw(&hello), v.ja3_raw, "{}", v.name);
            assert_eq!(compute_ja3(&hello), v.ja3, "{}", v.name);
        }
    }

    /// JA4 of every vector equals the reference implementation's
    /// (external audit NET-008: complete vectors from the reference, not
    /// computed by this code). All are checked before failing, so a
    /// mismatch names every vector it affects.
    #[test]
    fn ja4_matches_the_reference_on_our_client_hellos() {
        let mut mismatches = Vec::new();
        for v in VECTORS {
            let hello = parse_client_hello(&(v.build)()).expect(v.name);
            let ja4 = compute_ja4(&hello);
            if ja4 != v.ja4 {
                mismatches.push(format!("{}: {ja4} != {}", v.name, v.ja4));
            }
        }
        assert!(mismatches.is_empty(), "{mismatches:#?}");
    }

    /// The JA4 specification's worked example
    /// (`t13d1516h2_8daaf6152771_e5627efa2ab1`), with and without GREASE
    /// values in every list.
    #[test]
    fn ja4_matches_the_specification_example() {
        for grease in [false, true] {
            let bytes = ja4_spec_example(&JA4_SPEC_SIGNATURE_ALGORITHMS, grease);
            let hello = parse_client_hello(&bytes).expect("parse");
            assert_eq!(
                compute_ja4(&hello),
                "t13d1516h2_8daaf6152771_e5627efa2ab1",
                "grease: {grease}"
            );
        }
    }

    /// External audit NET-008 (NN-AUD-331), the point the audit could not
    /// verify: without signature algorithms the extension-hash input has
    /// no `_`. The specification's vector: `0005,000a,000b,000d,0012,0015,
    /// 0017,001b,0023,002b,002d,0033,4469,ff01` = `6d807ffa2a79`
    /// (signature_algorithms present, its list empty).
    #[test]
    fn ja4_extension_hash_omits_the_separator_without_signature_algorithms() {
        let hello = parse_client_hello(&ja4_spec_example(&[], false)).expect("parse");
        assert_eq!(compute_ja4(&hello), "t13d1516h2_8daaf6152771_6d807ffa2a79");
    }

    /// External audit NET-008: no server_name extension is `i` (the
    /// client went to an address), never `n`; the reference's values for
    /// the `tls13-no-sni` and `no-sni-no-cipher` vectors.
    #[test]
    fn ja4_uses_i_when_sni_is_absent() {
        let bytes = build_record(
            0x0303,
            [0; 32],
            &[],
            &[0x1301],
            &[0],
            &[(EXT_ALPN, alpn_ext(&["h2"]))],
        );
        let hello = parse_client_hello(&bytes).expect("parse");
        let ja4 = compute_ja4(&hello);
        assert!(ja4.starts_with("t12i0101h2_"), "{ja4}");

        let hello = parse_client_hello(&tls13_no_sni()).expect("parse");
        assert_eq!(compute_ja4(&hello), "t13i1714h2_5b57614c22b0_3d5424432f57");
        let hello = parse_client_hello(&no_sni_no_cipher()).expect("parse");
        assert_eq!(compute_ja4(&hello), "t13i000100_000000000000_2cfe23c976cf");
    }

    /// The `d` is the extension's presence (JA4 specification, "SNI"): a
    /// server_name the canonical form refuses is still a name.
    #[test]
    fn ja4_marks_d_for_a_present_but_nonconforming_sni() {
        let bytes = build_record(
            0x0303,
            [0; 32],
            &[],
            &[0x1301],
            &[0],
            &[(EXT_SERVER_NAME, sni_ext("bad_host.example"))],
        );
        let hello = parse_client_hello(&bytes).expect("parse");
        assert_eq!(sni(&hello), Sni::NonConforming);
        assert!(compute_ja4(&hello).starts_with("t12d0101"));
    }

    /// The ALPN pair as the reference implementations print it (their
    /// `first_last`): one character is both ends, an empty first value is
    /// `00`, a byte outside ASCII is `9`.
    #[test]
    fn ja4_alpn_pair_follows_the_reference_implementations() {
        let pair = |protocols: &[&[u8]]| {
            let bytes = build_record(
                0x0303,
                [0; 32],
                &[],
                &[0x1301],
                &[0],
                &[(EXT_ALPN, alpn_ext_bytes(protocols))],
            );
            ja4_alpn_pair(&parse_client_hello(&bytes).expect("parse"))
        };
        assert_eq!(pair(&[b"h2".as_slice()]), "h2");
        assert_eq!(pair(&[b"http/1.1".as_slice(), b"h2"]), "h1");
        assert_eq!(pair(&[b"x".as_slice()]), "xx");
        assert_eq!(pair(&[b"".as_slice()]), "00");
        assert_eq!(pair(&[]), "00");
        assert_eq!(pair(&[[0xBA, 0xAD].as_slice(), b"http/1.1"]), "99");
        assert_eq!(pair(&[[b'x', 0xFF].as_slice()]), "x9");
        assert_eq!(pair(&[[0xFF, b'x'].as_slice()]), "9x");
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
        assert_eq!(sni(&hello), Sni::Absent);
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

    /// The handshake message alone: a name of 65,000 bytes does not fit
    /// in one record.
    fn sni_of(ext_data: Vec<u8>) -> Sni {
        let bytes = build_handshake(
            0x0303,
            [0; 32],
            &[],
            &[0x1301],
            &[0],
            Some(&[(EXT_SERVER_NAME, ext_data)]),
        );
        sni(&parse_client_hello(&bytes).expect("parse"))
    }

    /// External audit NET-014 (NN-AUD-333): the SNI is canonical and
    /// bounded at the parser. One host in three spellings is one string;
    /// a name that is not a DNS host name is a flag, not the peer's string.
    #[test]
    fn sni_is_canonicalised_and_bounded() {
        for spelling in ["evil.example.com", "EVIL.Example.COM", "evil.example.com."] {
            assert_eq!(
                sni_of(sni_ext(spelling)),
                Sni::Host("evil.example.com".into()),
                "{spelling}"
            );
        }
        let label63 = "a".repeat(63);
        let max = format!("{label63}.{label63}.{label63}.{}", "b".repeat(61));
        assert_eq!(max.len(), 253);
        assert_eq!(sni_of(sni_ext(&max)), Sni::Host(max.clone()));
        assert_eq!(sni_of(sni_ext(&format!("{max}."))), Sni::Host(max.clone()));
        assert_eq!(sni_of(sni_ext(&format!("{max}b"))), Sni::NonConforming);
        assert_eq!(sni_of(sni_ext(&"a".repeat(300))), Sni::NonConforming);
        assert_eq!(
            sni_of(sni_ext(&format!("{}.example", "a".repeat(64)))),
            Sni::NonConforming
        );
        for bad in [
            "",
            ".",
            "a..b",
            ".a",
            "a b",
            "a_b.example",
            "a\u{7f}b",
            "a\nb",
            "ex\u{e4}mple.com",
            "a/b",
            "*.example.com",
        ] {
            assert_eq!(sni_of(sni_ext(bad)), Sni::NonConforming, "{bad:?}");
        }
        assert_eq!(sni_of(sni_ext_bytes(&[b'a', 0xFF])), Sni::NonConforming);
        assert_eq!(
            sni_of(sni_ext("xn--bcher-kva.example")),
            Sni::Host("xn--bcher-kva.example".into())
        );
        // A 65,535-byte name the peer chose is not kept.
        let huge = vec![b'a'; 65_000];
        assert_eq!(sni_of(sni_ext_bytes(&huge)), Sni::NonConforming);
    }

    /// External audit NET-014: an entry is read inside the declared
    /// server_name_list, not the extension; two host names, an empty list
    /// or no host name is not a server name the evidence can trust.
    #[test]
    fn sni_reads_stay_inside_the_declared_list() {
        let mut short_list = sni_ext("example.com");
        short_list[..2].copy_from_slice(&3u16.to_be_bytes());
        assert_eq!(sni_of(short_list), Sni::NonConforming);

        let mut two = Vec::new();
        for host in ["a.example", "b.example"] {
            two.push(SNI_TYPE_HOSTNAME);
            two.extend_from_slice(&(host.len() as u16).to_be_bytes());
            two.extend_from_slice(host.as_bytes());
        }
        let mut ext = (two.len() as u16).to_be_bytes().to_vec();
        ext.extend_from_slice(&two);
        assert_eq!(sni_of(ext), Sni::NonConforming);

        assert_eq!(sni_of(vec![0, 0]), Sni::NonConforming);
        assert_eq!(sni_of(vec![]), Sni::NonConforming);
        // Another name type only.
        assert_eq!(sni_of(vec![0, 4, 7, 0, 1, b'x']), Sni::NonConforming);
    }

    /// External audit NET-013 (NN-AUD-332): a list longer than the
    /// extension holding it is malformed and reads as empty; nothing is
    /// sized from its declared length.
    #[test]
    fn overlong_extension_lists_give_empty_lists() {
        let mut groups = supported_groups_ext(&[0x001D, 0x0017]);
        groups[..2].copy_from_slice(&0xFFFEu16.to_be_bytes());
        let mut algs = signature_algorithms_ext(&[0x0403]);
        algs[..2].copy_from_slice(&0xFFFEu16.to_be_bytes());
        let mut alpn = alpn_ext(&["h2"]);
        alpn[..2].copy_from_slice(&0xFFFFu16.to_be_bytes());
        let mut versions = supported_versions_ext(&[0x0304]);
        versions[0] = 0xFE;
        let bytes = build_record(
            0x0303,
            [0; 32],
            &[],
            &[0x1301],
            &[0],
            &[
                (EXT_SUPPORTED_GROUPS, groups),
                (EXT_SIGNATURE_ALGORITHMS, algs),
                (EXT_ALPN, alpn),
                (EXT_SUPPORTED_VERSIONS, versions),
            ],
        );
        let hello = parse_client_hello(&bytes).expect("parse");
        assert!(extract_supported_groups(&hello).is_empty());
        assert!(extract_signature_algorithms(&hello).is_empty());
        assert!(extract_alpn(&hello).is_empty());
        assert!(extract_supported_versions(&hello).is_empty());
        assert_eq!(compute_ja3_raw(&hello), "771,4865,10-13-16-43,,");
        // supported_versions there but unreadable: version unknown.
        assert!(
            compute_ja4(&hello).starts_with("t00i0104"),
            "{}",
            compute_ja4(&hello)
        );
    }

    /// JA3 reads the last supported_groups / ec_point_formats extension
    /// when a ClientHello repeats one, as `python/ja3.py` does (its loop
    /// keeps the last); the extension list names both (the reference's
    /// values for the `repeated-curves` vector).
    #[test]
    fn ja3_reads_the_last_repeated_curve_extension_like_the_reference() {
        let hello = parse_client_hello(&repeated_curves()).expect("parse");
        assert_eq!(compute_ja3_raw(&hello), "771,4865,10-11-10-11,29-24,0");
        assert_eq!(compute_ja3(&hello), "ab7326fb2d6e0c3cfe8ba3782e68a9a0");
    }

    // ── Record layer and message bounds (NET-018) ─────────────────────

    /// External audit NET-018 (NN-AUD-336): the record layer splits a
    /// ClientHello into several records; the fingerprints are the
    /// reference's for the unsplit vector. Cuts inside the handshake
    /// header and one byte per record are included.
    #[test]
    fn fragmented_client_hello_yields_the_same_ja3() {
        for v in VECTORS {
            let single = (v.build)();
            let hs_len = single.len() - RECORD_HEADER_LEN;
            for cuts in [
                vec![hs_len / 2],
                vec![2],
                vec![1, 2, 3, 4, 5],
                vec![40, 41, hs_len - 1],
                (1..hs_len).step_by(97).collect::<Vec<_>>(),
                (1..hs_len).step_by(13).collect::<Vec<_>>(),
            ] {
                let fragmented = refragment(&single, &cuts);
                let hello = parse_client_hello(&fragmented)
                    .unwrap_or_else(|| panic!("{} cut at {cuts:?}", v.name));
                assert_eq!(compute_ja4(&hello), v.ja4, "{} {cuts:?}", v.name);
                assert_eq!(compute_ja3(&hello), v.ja3, "{} {cuts:?}", v.name);
                assert_eq!(
                    parse_client_hello(&single).as_ref(),
                    Some(&hello),
                    "{}",
                    v.name
                );
            }
        }
    }

    /// External audit NET-018: what follows the ClientHello — in its
    /// record or after it — is not its extensions. The JA3 README's
    /// extension-less vector stays `de350869…` with bytes that parse as
    /// an extension block (`00 04 | 00 17 00 00`, extended_master_secret)
    /// after the message.
    #[test]
    fn trailing_bytes_are_not_parsed_as_extensions() {
        let hs = build_handshake(
            0x0301,
            [0; 32],
            &[],
            &[4, 5, 10, 9, 100, 98, 3, 6, 19, 18, 99],
            &[0],
            None,
        );
        let trailing = [0x00, 0x04, 0x00, 0x17, 0x00, 0x00];
        let mut in_record = hs.clone();
        in_record.extend_from_slice(&trailing);
        let mut after_record = record(&hs);
        after_record.extend_from_slice(&trailing);
        let mut ccs_after = record(&hs);
        ccs_after.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
        let mut handshake_form = hs.clone();
        handshake_form.extend_from_slice(&trailing);
        for (what, bytes) in [
            ("inside the record", record(&in_record)),
            ("after the record", after_record),
            ("a ChangeCipherSpec after it", ccs_after),
            ("after the handshake message", handshake_form),
        ] {
            let hello = parse_client_hello(&bytes).unwrap_or_else(|| panic!("{what}"));
            assert!(hello.extensions.is_empty(), "{what}");
            assert_eq!(
                compute_ja3(&hello),
                "de350869b8c85de67a350c8d186f11e6",
                "{what}"
            );
        }
    }

    /// External audit NET-018: a buffer that ends inside a ClientHello is
    /// `Incomplete` — at every byte, in one record, in many, or as the
    /// bare handshake message — and the whole is `Complete`.
    #[test]
    fn every_prefix_of_a_client_hello_is_incomplete() {
        let single = vector("tls13-h2");
        let fragmented = refragment(&single, &[3, 200, 201, 300]);
        let handshake = single[RECORD_HEADER_LEN..].to_vec();
        let no_extensions = record(&build_handshake(
            0x0301,
            [7; 32],
            &[1; 8],
            &[4, 5],
            &[0],
            None,
        ));
        for (what, full) in [
            ("one record", &single),
            ("five records", &fragmented),
            ("handshake message", &handshake),
            ("TLS 1.0 without extensions", &no_extensions),
        ] {
            for cut in 0..full.len() {
                assert_eq!(
                    parse_client_hello_outcome(&full[..cut]),
                    ClientHelloParse::Incomplete,
                    "{what}, cut at {cut}"
                );
            }
            assert!(
                matches!(
                    parse_client_hello_outcome(full),
                    ClientHelloParse::Complete(_)
                ),
                "{what}"
            );
        }
    }

    /// External audit NET-018: record layers and messages that are not a
    /// ClientHello's are `Invalid`, not `Incomplete`.
    #[test]
    fn a_broken_record_layer_or_message_is_invalid() {
        let single = vector("tls13-h2");
        let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();

        let mut foreign = refragment(&single, &[100]);
        foreign[RECORD_HEADER_LEN + 100] = 0x17; // application data mid-message
        cases.push(("a record of another type", foreign));

        let mut empty = record(&[]);
        empty.extend_from_slice(&single);
        cases.push(("an empty record", empty));

        let mut oversized = single.clone();
        oversized[3..5].copy_from_slice(&((MAX_RECORD_LEN + 1) as u16).to_be_bytes());
        cases.push(("a record over 2^14 bytes", oversized));

        let mut major = single.clone();
        major[1] = 0x02;
        cases.push(("a record version 2.x", major));

        let mut server_hello = single.clone();
        server_hello[RECORD_HEADER_LEN] = 0x02;
        cases.push(("a ServerHello", server_hello));

        let mut header_cut = refragment(&single, &[100])[..RECORD_HEADER_LEN + 100].to_vec();
        header_cut.extend_from_slice(&[0x17, 0x03]);
        cases.push(("a foreign record header at the end", header_cut));

        // Session id over 32 bytes.
        let mut long_sid = single.clone();
        long_sid[RECORD_HEADER_LEN + 4 + 2 + 32] = 33;
        cases.push(("a 33-byte session id", long_sid));

        // A byte inside the ClientHello after its extensions block.
        let hs = build_handshake(0x0303, [0; 32], &[], &[0x1301], &[0], Some(&[]));
        let mut body = hs[HANDSHAKE_HEADER_LEN..].to_vec();
        body.push(0);
        let mut padded = vec![HS_CLIENT_HELLO];
        padded.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        padded.extend_from_slice(&body);
        cases.push(("a byte after the extensions block", record(&padded)));

        for (what, bytes) in cases {
            assert_eq!(
                parse_client_hello_outcome(&bytes),
                ClientHelloParse::Invalid,
                "{what}"
            );
        }
    }

    /// External audit NET-013 and NET-020 (2) (NN-AUD-332, NN-AUD-434): a
    /// cipher list longer than the message holding it is rejected before
    /// anything is sized from it (the old `> u16::MAX` check could never
    /// fire); an odd length too.
    #[test]
    fn overlong_cipher_list_is_rejected() {
        let hs = build_handshake(0x0303, [0; 32], &[], &[0x1301, 0x1302], &[0], Some(&[]));
        let cipher_len_at = HANDSHAKE_HEADER_LEN + 2 + 32 + 1;
        for declared in [0xFFFEu16, 6, 3] {
            let mut bad = hs.clone();
            bad[cipher_len_at..cipher_len_at + 2].copy_from_slice(&declared.to_be_bytes());
            assert_eq!(
                parse_client_hello_outcome(&record(&bad)),
                ClientHelloParse::Invalid,
                "{declared}"
            );
            assert_eq!(
                parse_client_hello_outcome(&bad),
                ClientHelloParse::Invalid,
                "{declared}"
            );
        }
    }

    // ── Defensive parse tests ─────────────────────────────────────────

    /// N5 test #10 — malformed packet (wrong record type)
    /// returns None without panicking.
    #[test]
    fn parse_malformed_packet_returns_none_no_panic() {
        // Wrong record type byte (0x14 = ChangeCipherSpec).
        let bytes = vec![0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
        assert!(parse_client_hello(&bytes).is_none());
        assert_eq!(
            parse_client_hello_outcome(&bytes),
            ClientHelloParse::Invalid
        );
    }

    /// N5 test #11 — truncated packet doesn't panic and yields no
    /// ClientHello. Every strict prefix is a ClientHello cut short
    /// (external audit NET-018: the message is bounded by its own
    /// length, so a cut on a section boundary no longer passes for a
    /// TLS 1.0 hello without extensions).
    #[test]
    fn parse_truncated_packet_returns_none_no_panic() {
        let full = chrome_shaped_hello();
        for cut in 0..full.len() {
            assert!(parse_client_hello(&full[..cut]).is_none(), "cut at {cut}");
        }
        assert!(parse_client_hello(&full).is_some());
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

    /// The JA3 and JA4 of `hello` keep their shape whatever the lists hold
    /// (the `tls_client_hello` fuzz target asserts the same on every
    /// parsed input, external audit WDG-R08, NN-AUD-374).
    fn assert_fingerprint_shape(hello: &TlsClientHello) -> (String, String) {
        let raw = compute_ja3_raw(hello);
        assert_eq!(raw.split(',').count(), 5, "{raw}");
        let ja3 = compute_ja3(hello);
        assert!(
            ja3.len() == 32 && ja3.bytes().all(|b| b.is_ascii_hexdigit()),
            "{ja3}"
        );
        let ja4 = compute_ja4(hello);
        let parts: Vec<&str> = ja4.rsplitn(3, '_').collect();
        assert_eq!(parts.len(), 3, "{ja4}");
        for hash in &parts[..2] {
            assert!(
                hash.len() == 12 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
                "{ja4}"
            );
        }
        (raw, ja4)
    }

    /// External audit WDG-R08 (NN-AUD-374): no cipher suite. JA3 keeps an
    /// empty field, JA4 counts zero and uses the empty-list hash.
    #[test]
    fn zero_cipher_hello_fingerprints() {
        let bytes = build_record(
            0x0303,
            [1; 32],
            &[],
            &[],
            &[0],
            &[(EXT_SERVER_NAME, sni_ext("a.example"))],
        );
        let hello = parse_client_hello(&bytes).expect("parses");
        assert!(hello.cipher_suites.is_empty());
        let (raw, ja4) = assert_fingerprint_shape(&hello);
        assert_eq!(raw, "771,,0,,");
        assert!(ja4.starts_with("t12d0001"), "{ja4}");
        assert_eq!(ja4.split('_').nth(1), Some(JA4_EMPTY_HASH));
    }

    /// External audit WDG-R08: an empty extensions block, and none at all
    /// (TLS 1.0 shape).
    #[test]
    fn zero_extension_hello_fingerprints() {
        let bytes = build_record(0x0301, [2; 32], &[7; 32], &[0x002F], &[0], &[]);
        let hello = parse_client_hello(&bytes).expect("parses");
        assert!(hello.extensions.is_empty());
        let (raw, ja4) = assert_fingerprint_shape(&hello);
        assert_eq!(raw, "769,47,,,");
        assert_eq!(ja4, format!("t10i010000_{}_{JA4_EMPTY_HASH}", &ja4[11..23]));
        // the same hello ending after the compression methods: no block at
        // all, the record and handshake lengths shortened to match (a cut
        // without them is an incomplete message since lab PR 202)
        let mut none = bytes[..bytes.len() - 2].to_vec();
        let rec = u16::from_be_bytes([none[3], none[4]]) - 2;
        none[3..5].copy_from_slice(&rec.to_be_bytes());
        let hs = u32::from_be_bytes([0, none[6], none[7], none[8]]) - 2;
        none[6..9].copy_from_slice(&hs.to_be_bytes()[1..]);
        let hello = parse_client_hello(&none).expect("parses without a block");
        assert!(hello.extensions.is_empty());
        assert_eq!(compute_ja3_raw(&hello), raw);
    }

    /// External audit WDG-R08: an ALPN extension with an empty list, and
    /// one whose first protocol is empty, both read as no ALPN ("00").
    #[test]
    fn empty_alpn_reads_as_none() {
        for alpn in [alpn_ext(&[]), alpn_ext(&["", "h2"])] {
            let bytes = build_record(0x0303, [3; 32], &[], &[0x1301], &[0], &[(EXT_ALPN, alpn)]);
            let hello = parse_client_hello(&bytes).expect("parses");
            let (_, ja4) = assert_fingerprint_shape(&hello);
            assert_eq!(&ja4[..10], "t12i010100", "{ja4}");
        }
    }

    /// External audit WDG-R08: 4,000 extensions — as many as one TLS
    /// record of at most 2^14 bytes holds (lab PR 202 enforces the record
    /// limit) — parse, and JA4 caps the count at 99.
    #[test]
    fn four_thousand_extensions_parse_and_cap_the_count() {
        // from 0x0100 (none JA3/JA4 reads), the filter's GREASE shape left out
        let exts: Vec<(u16, Vec<u8>)> = (0x0100u16..)
            .filter(|t| !is_grease_u16(*t))
            .take(4000)
            .map(|t| (t, Vec::new()))
            .collect();
        let bytes = build_record(0x0303, [4; 32], &[], &[0x1301], &[0], &exts);
        let hello = parse_client_hello(&bytes).expect("parses");
        assert_eq!(hello.extensions.len(), 4000);
        let (raw, ja4) = assert_fingerprint_shape(&hello);
        assert_eq!(raw.split(',').nth(2).unwrap().split('-').count(), 4000);
        assert_eq!(&ja4[..10], "t12i019900", "{ja4}");
    }

    /// Hostile input: mutations of the reference vectors (bytes flipped,
    /// lengths set to extremes, cuts) never panic, and whatever parses
    /// fingerprints without panicking. A sample of what the
    /// `tls_client_hello` fuzz target covers.
    #[test]
    fn mutated_client_hellos_never_panic() {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for v in VECTORS {
            let base = (v.build)();
            for _ in 0..1500 {
                let mut m = base.clone();
                for _ in 0..(1 + next() % 4) {
                    let at = (next() as usize) % m.len();
                    m[at] = match next() % 4 {
                        0 => 0x00,
                        1 => 0xFF,
                        _ => next() as u8,
                    };
                }
                if next() % 3 == 0 {
                    let keep = (next() as usize) % m.len();
                    m.truncate(keep);
                }
                if let Some(hello) = parse_client_hello(&m) {
                    let _ = (compute_ja3(&hello), compute_ja4(&hello), sni(&hello));
                    let _ = extract_alpn(&hello);
                }
            }
        }
    }

    /// Lab PR 230 (D0 of the dependency plan): JA3's MD5 as computed today,
    /// pinned before the md-5 0.11 bump (the reference vectors above pin it
    /// too; this is the value `compute_ja3_matches_published_chrome_120_value`
    /// only recomputes).
    mod crypto_vectors {
        use super::*;

        /// Protects: a JA3 a rule or a feed recorded before the bump still matches after it.
        #[test]
        fn ja3_md5_is_pinned() {
            let hello = parse_client_hello(&chrome_shaped_hello()).expect("parse");
            assert_eq!(
                compute_ja3_raw(&hello),
                "771,4865-4866-4867,0-10-11-13-16-43,29-23,0"
            );
            assert_eq!(compute_ja3(&hello), "7c8b1b3287298e5d9d59f8e6cb769274");
        }
    }

    /// Lab PR 242 (R06 of the Wave 4 restructure): what the parser makes of
    /// bytes, pinned on `main` before the file moved from the agent to
    /// nn-parse and unchanged after — on the `tls_client_hello` fuzz seeds
    /// every field and fingerprint, and on a corpus of hostile inputs
    /// (every prefix and mutants of the seeds and the reference vectors) a
    /// SHA-256 over everything each input parses to.
    mod output_pins {
        use super::*;

        /// The fuzz seeds (fuzz/seeds/tls_client_hello), the bytes the fuzz
        /// job replays: one record-wrapped hello, one handshake message.
        const SEEDS: [(&str, &[u8]); 2] = [
            (
                "chrome-shaped",
                include_bytes!(concat!(
                    env!("NN_REPO_ROOT"),
                    "/fuzz/seeds/tls_client_hello/chrome-shaped.bin"
                )),
            ),
            (
                "curl-shaped-handshake-only",
                include_bytes!(concat!(
                    env!("NN_REPO_ROOT"),
                    "/fuzz/seeds/tls_client_hello/curl-shaped-handshake-only.bin"
                )),
            ),
        ];

        /// Everything the parser makes of `bytes`, on one line: the outcome
        /// and, for a complete hello, its fields, the SNI both ways, the
        /// ALPN, JA3's input, JA3 (MD5) and JA4.
        fn render(bytes: &[u8]) -> String {
            let hello = match parse_client_hello_outcome(bytes) {
                ClientHelloParse::Complete(hello) => hello,
                other => {
                    assert_eq!(parse_client_hello(bytes), None);
                    return format!("{other:?}");
                }
            };
            assert_eq!(parse_client_hello(bytes).as_ref(), Some(&hello));
            let extensions: Vec<String> = hello
                .extensions
                .iter()
                .map(|e| format!("{}:{}", e.ext_type, hex::encode(&e.data)))
                .collect();
            format!(
                "Complete version={} random={} session_id={} ciphers={:?} compression={:?} \
                 extensions=[{}] sni={:?} extract_sni={:?} alpn={:?} ja3_raw={} ja3={} ja4={}",
                hello.version,
                hex::encode(hello.random),
                hex::encode(&hello.session_id),
                hello.cipher_suites,
                hello.compression_methods,
                extensions.join(" "),
                sni(&hello),
                extract_sni(&hello),
                extract_alpn(&hello),
                compute_ja3_raw(&hello),
                compute_ja3(&hello),
                compute_ja4(&hello),
            )
        }

        /// Protects: the seeds parse to the same fields and fingerprints
        /// wherever the parser lives.
        #[test]
        fn the_fuzz_seeds_parse_to_the_pinned_fingerprints() {
            let want = [
                concat!(
                    "Complete version=771 ",
                    "random=4242424242424242424242424242424242424242424242424242424242424242 ",
                    "session_id= ciphers=[2570, 4865, 4866, 4867] compression=[0] ",
                    "extensions=[43690: 0:000e00000b6578616d706c652e636f6d 10:0004001d0017 ",
                    "11:0100 13:000404030804 16:000c02683208687474702f312e31 43:0403040303] ",
                    "sni=Host(\"example.com\") extract_sni=Some(\"example.com\") ",
                    "alpn=[\"h2\", \"http/1.1\"] ",
                    "ja3_raw=771,4865-4866-4867,0-10-11-13-16-43,29-23,0 ",
                    "ja3=7c8b1b3287298e5d9d59f8e6cb769274 ja4=t13d0306h2_55b375c5d22e_fb71836bce29"
                ),
                concat!(
                    "Complete version=771 ",
                    "random=0707070707070707070707070707070707070707070707070707070707070707 ",
                    "session_id=1111111111111111111111111111111111111111111111111111111111111111 ",
                    "ciphers=[4866, 4867, 4865, 49196, 49200, 159] compression=[0] ",
                    "extensions=[0:001200000f6170692e6578616d706c652e6f7267 11:03000102 ",
                    "10:0006001d00170018 16:000908687474702f312e31 13:00080403050306030804 ",
                    "43:0403040303] ",
                    "sni=Host(\"api.example.org\") extract_sni=Some(\"api.example.org\") ",
                    "alpn=[\"http/1.1\"] ",
                    "ja3_raw=771,4866-4867-4865-49196-49200-159,0-11-10-16-13-43,29-23-24,0-1-2 ",
                    "ja3=50a5c09058ba3dfce127ba686a35b8d4 ja4=t13d0606h1_50064deaa0fd_453946b46bd2"
                ),
            ];
            for ((name, bytes), want) in SEEDS.iter().zip(want) {
                assert_eq!(render(bytes), want, "{name}");
            }
        }

        /// Every prefix of each seed and reference vector (the incomplete
        /// hellos and the cut records), then 300 mutants of each: one to
        /// four bytes set to 0x00, 0xFF or a random value, a third of them
        /// then cut short — from a fixed xorshift stream.
        fn hostile_corpus() -> Vec<Vec<u8>> {
            let mut bases: Vec<Vec<u8>> = SEEDS.iter().map(|(_, b)| b.to_vec()).collect();
            bases.extend(VECTORS.iter().map(|v| (v.build)()));
            let mut state = 0x9E37_79B9_7F4A_7C15u64;
            let mut next = move || {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            };
            let mut out = Vec::new();
            for base in &bases {
                out.extend((0..=base.len()).map(|n| base[..n].to_vec()));
                for _ in 0..300 {
                    let mut m = base.clone();
                    for _ in 0..(1 + next() % 4) {
                        let at = (next() as usize) % m.len();
                        m[at] = match next() % 4 {
                            0 => 0x00,
                            1 => 0xFF,
                            _ => next() as u8,
                        };
                    }
                    if next() % 3 == 0 {
                        let keep = (next() as usize) % m.len();
                        m.truncate(keep);
                    }
                    out.push(m);
                }
            }
            out
        }

        /// Protects: hostile bytes parse to the same outcome, fields and
        /// fingerprints wherever the parser lives — the corpus's renderings
        /// in order, hashed; the counts say all three outcomes are covered.
        #[test]
        fn a_hostile_corpus_parses_to_the_pinned_digest() {
            let mut all = String::new();
            let (mut complete, mut incomplete, mut invalid) = (0usize, 0usize, 0usize);
            for input in hostile_corpus() {
                match parse_client_hello_outcome(&input) {
                    ClientHelloParse::Complete(_) => complete += 1,
                    ClientHelloParse::Incomplete => incomplete += 1,
                    ClientHelloParse::Invalid => invalid += 1,
                }
                all.push_str(&render(&input));
                all.push('\n');
            }
            assert_eq!((complete, incomplete, invalid), (1840, 3842, 877));
            assert_eq!(
                hex::encode(Sha256::digest(all.as_bytes())),
                "b395f945cdb9c32a2a0e4a99286b0f0d4b3475965b2c16c32c3903924b7052fc"
            );
        }
    }
}

/// Kani proofs (Tappa 10.8, "verifica formale dopo il fuzzing"). Every byte
/// the ClientHello parser reads goes through [`Cursor`]; if each cursor
/// operation is panic-free and keeps `pos <= buf.len()`, any sequence of
/// them is — so the parser cannot index out of bounds on any input, which
/// the fuzzer can only sample.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    const N: usize = 8;

    #[kani::proof]
    fn cursor_operations_never_panic_and_keep_pos_in_bounds() {
        let backing: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let pos: usize = kani::any();
        kani::assume(pos <= len);
        let mut c = Cursor {
            buf: &backing[..len],
            pos,
        };
        let n: usize = kani::any(); // any length an attacker-controlled field can carry
        match kani::any::<u8>() % 4 {
            0 => {
                let _ = c.read_u8();
            }
            1 => {
                let _ = c.read_u16();
            }
            2 => {
                let _ = c.read_u24();
            }
            _ => {
                if let Some(b) = c.read_bytes(n) {
                    assert!(b.len() == n);
                }
            }
        }
        assert!(c.pos <= len);
    }
}
