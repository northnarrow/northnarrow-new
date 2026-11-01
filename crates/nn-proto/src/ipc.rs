//! The core ↔ worker IPC (Wave 4 restructure, R14a — plan §3.5;
//! `docs/architecture/PROCESS_MODEL.md`).
//!
//! The agent's core starts its workers — the same binary, `--worker <kind>
//! --ipc-fd 3`, as the unprivileged `northnarrow-worker` account — and
//! talks to each over one `socketpair(AF_UNIX, SOCK_SEQPACKET)`: one
//! message per packet, the kernel keeps the boundaries. This module is the
//! protocol, pure (no socket here: nn-linux's `worker::transport` moves the
//! packets):
//!
//! - a packet is one postcard-encoded message of at most [`MAX_FRAME`]
//!   bytes, read whole ([`decode`] refuses trailing bytes);
//! - the worker speaks first: [`WorkerHello`] — the protocol's
//!   [`IPC_VERSION`], its kind, its pid and the sandbox it entered
//!   ([`SandboxLevel`]); the core checks every field ([`check_hello`])
//!   before it sends anything;
//! - then requests and responses: each request carries an id the core
//!   chose, strictly increasing; a worker answers the oldest request it
//!   holds, once ([`Response::id`]); anything else — an unknown id, an
//!   answer of the wrong kind, a second hello, a packet the core did not
//!   ask for — is a protocol violation, and the core kills the worker;
//! - every typed result is checked again by the core against the request
//!   it answers ([`check_response`]): its sizes, and the alphabet of every
//!   string. The core never parses the input itself, so it cannot compare
//!   the result with its own; it bounds what a lying worker can hand it.
//!
//! No descriptor ever crosses this channel: the requests carry their bytes
//! (a QNAME is at most a few hundred, a ClientHello's record 16 KiB, a DNS
//! answer 64 KiB at most in a frame), so neither `SCM_RIGHTS` nor a sealed
//! memfd is needed, and the core reads with no control buffer: a
//! descriptor a worker sends is closed by the kernel and the packet is
//! refused (`MSG_CTRUNC`). The exec quarantine's scanner (lab PR 223) is
//! where a descriptor must cross (the file to hash, a sealed memfd for its
//! configuration): its own protocol, `crate::execq`.
//!
//! Review of #480 (F1): a worker's strings are read as bytes only — a
//! `&str` sliced at an index a lying worker chose panics at a character's
//! middle, and the agent's release profile aborts on a panic. No slice,
//! no index here that can panic: the two lints below hold it.
#![deny(clippy::string_slice, clippy::indexing_slicing)]

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// The protocol's version: a worker that says another one is refused. 2
/// (R14b): a name's `form` (an NSS record's text), the parse worker's names
/// in production.
pub const IPC_VERSION: u16 = 2;

/// Largest packet either side sends or accepts (plan §3.5: 64 KiB).
pub const MAX_FRAME: usize = 64 * 1024;

/// Most items one batched request may carry.
pub const MAX_BATCH: usize = 512;

/// The most a batch of names may need of its answer's frame: each name's
/// longest decode ([`max_qname_out`]) and its encoding's overhead
/// ([`NAME_OVERHEAD`]), within [`MAX_FRAME`] less [`FRAME_MARGIN`]. A request
/// whose worst answer would not fit a frame is refused before it is sent:
/// an honest worker can always answer what it is asked.
pub const fn worst_answer(name_bytes: usize) -> usize {
    max_qname_out(name_bytes) + NAME_OVERHEAD
}

/// The bytes postcard spends on one name's answer beyond its text (the
/// string's length, the end's option and value), rounded up.
pub const NAME_OVERHEAD: usize = 8;

/// The frame's room kept for the envelope (the response's id, the variant
/// tags, the vector's length).
pub const FRAME_MARGIN: usize = 64;

/// Longest QNAME input: the kernel's record holds `QNAME_WIRE_LEN` (288)
/// bytes; the bound leaves room for a larger record without letting a
/// request carry more than a name.
pub const MAX_QNAME_IN: usize = 512;

/// Longest decoded name a worker may return for an input of `n` bytes:
/// every byte as `\DDD` (four characters), and one `…` (three bytes in
/// UTF-8) for a compression pointer.
pub const fn max_qname_out(n: usize) -> usize {
    4 * n + 3
}

/// Longest ClientHello input (one TLS record's fragment, 2^14, and its
/// records' headers, for a hello split across records).
pub const MAX_TLS_IN: usize = 32 * 1024;

/// Longest DNS answer input.
pub const MAX_DNS_ANSWER_IN: usize = 60 * 1024;

/// Longest string field of a TLS result (an ALPN name is at most 255 bytes
/// on the wire; JA3/JA4 are fixed-size).
pub const MAX_TLS_FIELD: usize = 255;

/// Most ALPN names a TLS result carries.
pub const MAX_ALPN: usize = 64;

/// An ALPN name as a worker hands it on (review of #480, F9): printable
/// ASCII only — a byte outside `!`..`~` but the space, and the backslash
/// itself, written `\xHH` — cut to [`MAX_TLS_FIELD`] bytes at a whole
/// escape. The core accepts nothing else ([`check_response`]): a name it
/// logs or matches cannot carry a control character or a line break.
pub fn alpn_display(raw: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::new();
    for &b in raw {
        let printable = (0x20..=0x7e).contains(&b) && b != b'\\';
        let need = if printable { 1 } else { 4 };
        if out.len() + need > MAX_TLS_FIELD {
            break;
        }
        if printable {
            out.push(char::from(b));
        } else {
            out.push('\\');
            out.push('x');
            out.push(char::from(
                HEX.get(usize::from(b >> 4)).copied().unwrap_or(b'0'),
            ));
            out.push(char::from(
                HEX.get(usize::from(b & 0xf)).copied().unwrap_or(b'0'),
            ));
        }
    }
    out
}

fn printable_ascii(s: &str) -> bool {
    s.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// A worker's kind: what it serves (plan §3.1). The name is its
/// `--worker` argument.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkerKind {
    /// nn-parse's parsers of hostile bytes: QNAMEs, DNS answers, the TLS
    /// ClientHello.
    Parse,
}

impl WorkerKind {
    pub const ALL: [WorkerKind; 1] = [WorkerKind::Parse];

    pub fn name(self) -> &'static str {
        match self {
            WorkerKind::Parse => "parse",
        }
    }

    pub fn from_name(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == s)
    }
}

/// How far a Landlock ruleset was enforced (the `landlock` crate's
/// `RulesetStatus`, in words the manifest prints).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum LandlockEnforced {
    /// Every right asked for is enforced.
    Full,
    /// Some: the kernel's ABI handles fewer rights than were asked for.
    Partial,
    /// None: Landlock is not built into the kernel, not enabled in its
    /// `lsm=`, or the ruleset could not be applied.
    #[default]
    None,
}

impl LandlockEnforced {
    pub fn as_str(self) -> &'static str {
        match self {
            LandlockEnforced::Full => "full",
            LandlockEnforced::Partial => "partial",
            LandlockEnforced::None => "none",
        }
    }
}

/// The sandbox a worker entered, measured by the worker after it entered
/// it (`nn_linux::sandbox::enter`) and declared in the signed capability
/// manifest (plan §5 risk 8: the Landlock ABI differs per kernel —
/// 5.15: 1, 6.1: 2, 6.8: 4, 6.12: 6 — declared, never assumed).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxLevel {
    /// The kernel's Landlock ABI version (0: not built in, or not enabled
    /// in `lsm=`).
    pub landlock_abi: u8,
    pub landlock: LandlockEnforced,
    /// Every filesystem right the ABI knows is handled, and no rule grants
    /// one: no path can be opened, created, removed or executed.
    pub fs_denied: bool,
    /// TCP bind and connect are handled with no rule (ABI ≥ 4).
    pub net_denied: bool,
    /// Signals and abstract UNIX sockets are scoped to the worker's own
    /// Landlock domain (ABI ≥ 6).
    pub scoped: bool,
    /// The seccomp allowlist is installed (kill the process on any other
    /// system call).
    pub seccomp: bool,
    /// `PR_GET_NO_NEW_PRIVS`.
    pub no_new_privs: bool,
    /// `PR_GET_DUMPABLE` (must be false: no core, no ptrace by its own
    /// user).
    pub dumpable: bool,
    /// Real, effective and saved ids are the same (`getresuid`,
    /// `getresgid`), so these are each of them.
    pub uid: u32,
    pub gid: u32,
    /// Supplementary groups (must be 0).
    pub groups: u32,
    /// `/proc/self/status`'s capability sets.
    pub cap_eff: u64,
    pub cap_prm: u64,
    pub cap_inh: u64,
    pub cap_amb: u64,
    pub cap_bnd: u64,
    /// The soft limits set (`RLIMIT_NOFILE`, `RLIMIT_NPROC`, `RLIMIT_CORE`).
    pub nofile: u64,
    pub nproc: u64,
    pub core: u64,
}

impl SandboxLevel {
    /// The level in one line for the journal, the status and the manifest:
    /// `landlock abi 4 full (fs, net) · seccomp · nnp · uid 998 · caps 0`.
    pub fn summary(&self) -> String {
        let mut ll = alloc::vec![];
        if self.fs_denied {
            ll.push("fs");
        }
        if self.net_denied {
            ll.push("net");
        }
        if self.scoped {
            ll.push("scope");
        }
        alloc::format!(
            "landlock abi {} {}{} · seccomp {} · no_new_privs {} · dumpable {} · uid {} gid {} groups {} · caps eff {:#x} prm {:#x} amb {:#x} bnd {:#x}",
            self.landlock_abi,
            self.landlock.as_str(),
            if ll.is_empty() {
                String::new()
            } else {
                alloc::format!(" ({})", ll.join(", "))
            },
            on_off(self.seccomp),
            on_off(self.no_new_privs),
            on_off(self.dumpable),
            self.uid,
            self.gid,
            self.groups,
            self.cap_eff,
            self.cap_prm,
            self.cap_amb,
            self.cap_bnd,
        )
    }
}

fn on_off(b: bool) -> &'static str {
    if b {
        "on"
    } else {
        "off"
    }
}

/// The worker's first packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerHello {
    pub version: u16,
    pub kind: WorkerKind,
    pub pid: u32,
    pub sandbox: SandboxLevel,
}

/// One DNS name to decode, as the kernel copied it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QnameIn {
    pub bytes: Vec<u8>,
    pub form: QnameForm,
}

/// What a name's bytes are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QnameForm {
    /// A query's name in wire form (the `udp_sendmsg` sensor's copy).
    Wire,
    /// A query's name in wire form with what follows it (the socket-buffer
    /// sensor's copy): its end, where the query type follows, is asked for.
    WireFindEnd,
    /// R14b: the text a process passed to systemd-resolved's NSS module
    /// (`dns_flags::NSS`), to its first NUL: its presentation form, empty
    /// when the name is.
    Nss,
}

/// A decoded QNAME.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QnameOut {
    /// The presentation form (`nn_parse::dns_qname::decode_dns_qname`).
    pub name: String,
    /// Where the name ends in the input (`qname_wire_end`), when asked for
    /// and found.
    pub end: Option<u16>,
}

/// The server_name of a ClientHello, as nn-parse's `Sni`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SniOut {
    Absent,
    Host(String),
    NonConforming,
}

/// What a ClientHello gave.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsOut {
    /// The message continues past the bytes given.
    Incomplete,
    /// Not a ClientHello.
    Invalid,
    Complete {
        /// MD5 of the JA3 string, 32 lower-case hex digits.
        ja3: String,
        /// `t13d1516h2_<12 hex>_<12 hex>`.
        ja4: String,
        sni: SniOut,
        alpn: Vec<String>,
    },
}

/// What the core asks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// Liveness: answered with [`Response::Pong`].
    Ping,
    /// QNAMEs, decoded in order, one answer each.
    DnsNames(Vec<QnameIn>),
    /// A TLS ClientHello (the record layer or the bare handshake message).
    TlsClientHello(Vec<u8>),
    /// A DNS response: its A and AAAA answers.
    DnsAnswers(Vec<u8>),
    /// `debug-trigger` builds' faults (the lab's worker crash and hang):
    /// the worker aborts, or stops answering. Last, so the production
    /// variants keep their numbers. A production worker refuses them
    /// ([`Response::Refused`]).
    DebugCrash,
    DebugHang,
}

impl Request {
    pub fn name(&self) -> &'static str {
        match self {
            Request::Ping => "ping",
            Request::DnsNames(_) => "dns_names",
            Request::TlsClientHello(_) => "tls_client_hello",
            Request::DnsAnswers(_) => "dns_answers",
            Request::DebugCrash => "debug_crash",
            Request::DebugHang => "debug_hang",
        }
    }

    /// The request is within the protocol's bounds (the core builds only
    /// such requests; the worker checks them too before it parses).
    pub fn check(&self) -> Result<(), Violation> {
        match self {
            Request::DnsNames(names) => {
                if names.is_empty() || names.len() > MAX_BATCH {
                    return Err(Violation::Bounds("dns_names: batch size"));
                }
                if names.iter().any(|q| q.bytes.len() > MAX_QNAME_IN) {
                    return Err(Violation::Bounds("dns_names: a name's bytes"));
                }
                // its worst answer fits a frame
                if names
                    .iter()
                    .map(|q| worst_answer(q.bytes.len()))
                    .sum::<usize>()
                    > MAX_FRAME - FRAME_MARGIN
                {
                    return Err(Violation::Bounds("dns_names: the answer's frame"));
                }
                Ok(())
            }
            Request::TlsClientHello(b) if b.len() > MAX_TLS_IN => {
                Err(Violation::Bounds("tls_client_hello: bytes"))
            }
            Request::DnsAnswers(b) if b.len() > MAX_DNS_ANSWER_IN => {
                Err(Violation::Bounds("dns_answers: bytes"))
            }
            _ => Ok(()),
        }
    }
}

/// Core → worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToWorker {
    pub id: u64,
    pub req: Request,
}

/// The worker's answer to one request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Answer {
    Pong,
    DnsNames(Vec<QnameOut>),
    Tls(TlsOut),
    DnsAnswers {
        a: Vec<[u8; 4]>,
        aaaa: Vec<[u8; 16]>,
    },
    /// The request was not served ([`Refusal`]: a closed set, review of
    /// #480 F9 — no free text from a worker).
    Refused(Refusal),
}

/// Why a worker did not serve a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Refusal {
    /// The request was out of the protocol's bounds ([`Request::check`]).
    OutOfBounds,
    /// A debug fault asked of a production worker.
    DebugOnly,
}

impl Refusal {
    pub fn as_str(self) -> &'static str {
        match self {
            Refusal::OutOfBounds => "out of the protocol's bounds",
            Refusal::DebugOnly => "debug faults exist only in lab builds",
        }
    }
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Worker → core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FromWorker {
    Hello(WorkerHello),
    Response(Response),
}

/// A response: the id of the request it answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Response {
    pub id: u64,
    pub answer: Answer,
}

/// Why the core refused what a worker sent: the worker is killed and the
/// refusal is a signed degradation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    /// The packet did not decode, or held trailing bytes.
    Malformed(String),
    /// A packet larger than [`MAX_FRAME`] (`MSG_TRUNC`).
    Oversized(usize),
    /// A packet carried a descriptor or other ancillary data
    /// (`MSG_CTRUNC`).
    Ancillary,
    /// The hello was not first, came twice, or failed [`check_hello`].
    Hello(String),
    /// A response to a request not outstanding, or not the oldest.
    UnknownId(u64),
    /// More packets than requests (a flood).
    Unsolicited,
    /// A result of the wrong kind for its request.
    WrongKind(&'static str),
    /// A result out of its bounds: a size, a count, a character.
    Bounds(&'static str),
    /// Review of #480 (F2): the worker left bytes of the core's earlier
    /// requests unread (an honest worker reads a request before it
    /// answers): it would fill the core's send buffer.
    Unread(usize),
}

impl core::fmt::Display for Violation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Violation::Malformed(e) => write!(f, "malformed packet: {e}"),
            Violation::Oversized(n) => write!(f, "packet of {n} bytes, above {MAX_FRAME}"),
            Violation::Ancillary => write!(f, "a packet carried a descriptor"),
            Violation::Hello(e) => write!(f, "hello refused: {e}"),
            Violation::UnknownId(id) => write!(f, "response to request {id}, not the oldest"),
            Violation::Unsolicited => write!(f, "a packet no request asked for"),
            Violation::WrongKind(k) => write!(f, "an answer of the wrong kind to {k}"),
            Violation::Bounds(what) => write!(f, "result out of bounds: {what}"),
            Violation::Unread(n) => write!(f, "{n} bytes of earlier requests left unread"),
        }
    }
}

/// postcard encoding of one message, refused above [`MAX_FRAME`].
pub fn encode<T: Serialize>(msg: &T) -> Result<Vec<u8>, String> {
    let bytes = postcard::to_allocvec(msg).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_FRAME {
        return Err(alloc::format!(
            "message of {} bytes exceeds {MAX_FRAME}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

/// One message from a packet; trailing bytes are an error.
pub fn decode<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, Violation> {
    if bytes.len() > MAX_FRAME {
        return Err(Violation::Oversized(bytes.len()));
    }
    let (v, rest) =
        postcard::take_from_bytes(bytes).map_err(|e| Violation::Malformed(e.to_string()))?;
    if !rest.is_empty() {
        return Err(Violation::Malformed(alloc::format!(
            "{} trailing bytes",
            rest.len()
        )));
    }
    Ok(v)
}

/// What the core expects of a worker: checked against its hello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected {
    pub kind: WorkerKind,
    /// The pid the core started.
    pub pid: u32,
    /// The `northnarrow-worker` account.
    pub uid: u32,
    pub gid: u32,
    /// The kernel's Landlock ABI as the core read it (review of #480, F7:
    /// the worker's declaration is checked against it).
    pub kernel_landlock_abi: u8,
}

/// The newest Landlock ABI a worker's build asks for (the `landlock`
/// crate's): a kernel above it gives no more.
pub const LANDLOCK_ABI_KNOWN: u8 = 9;

/// The core's check of a worker's hello (plan §3.5: the version handshake;
/// R14a: the sandbox it declares). A worker that entered less than its
/// sandbox — no seccomp filter, privileges it could still gain, a core it
/// could dump, a capability, another account, a group — is refused; the
/// Landlock part is declared, not required (the kernel's ABI decides it).
pub fn check_hello(h: &WorkerHello, want: &Expected) -> Result<(), Violation> {
    let bad = |s: String| Err(Violation::Hello(s));
    if h.version != IPC_VERSION {
        return bad(alloc::format!(
            "protocol {} (want {IPC_VERSION})",
            h.version
        ));
    }
    if h.kind != want.kind {
        return bad(alloc::format!(
            "kind {} (want {})",
            h.kind.name(),
            want.kind.name()
        ));
    }
    if h.pid != want.pid {
        return bad(alloc::format!("pid {} (started {})", h.pid, want.pid));
    }
    let s = &h.sandbox;
    if s.uid != want.uid || s.gid != want.gid || s.uid == 0 || s.gid == 0 {
        return bad(alloc::format!(
            "runs as {}:{} (want {}:{})",
            s.uid,
            s.gid,
            want.uid,
            want.gid
        ));
    }
    if s.groups != 0 {
        return bad(alloc::format!("{} supplementary groups", s.groups));
    }
    if !s.seccomp {
        return bad("no seccomp filter".into());
    }
    if !s.no_new_privs {
        return bad("no_new_privs not set".into());
    }
    if s.dumpable {
        return bad("dumpable".into());
    }
    if s.cap_eff != 0 || s.cap_prm != 0 || s.cap_inh != 0 || s.cap_amb != 0 {
        return bad(alloc::format!(
            "capabilities eff {:#x} prm {:#x} inh {:#x} amb {:#x}",
            s.cap_eff,
            s.cap_prm,
            s.cap_inh,
            s.cap_amb
        ));
    }
    if s.core != 0 || s.nproc != 0 {
        return bad(alloc::format!("limits core {} nproc {}", s.core, s.nproc));
    }
    // Review of #480 (F7): the ABI the worker read is the kernel's (as the
    // core read it), and the rights it measured are the ones that ABI
    // gives: a worker on a kernel with Landlock that is not under it, or
    // under less of it, is refused.
    let abi = want.kernel_landlock_abi.min(LANDLOCK_ABI_KNOWN);
    if s.landlock_abi != abi {
        return bad(alloc::format!(
            "landlock ABI {} declared, the kernel's is {}",
            s.landlock_abi,
            want.kernel_landlock_abi
        ));
    }
    if (abi >= 1 && (!s.fs_denied || s.landlock == LandlockEnforced::None))
        || (abi >= 4 && !s.net_denied)
        || (abi >= 6 && !s.scoped)
    {
        return bad(alloc::format!(
            "landlock below what ABI {abi} gives (fs {}, net {}, scope {})",
            s.fs_denied,
            s.net_denied,
            s.scoped
        ));
    }
    // A Landlock level the kernel's ABI cannot give is a lie.
    if s.landlock_abi == 0 && (s.landlock != LandlockEnforced::None || s.fs_denied) {
        return bad("landlock enforced without an ABI".into());
    }
    if (s.net_denied && s.landlock_abi < 4) || (s.scoped && s.landlock_abi < 6) {
        return bad(alloc::format!(
            "landlock rights above ABI {}",
            s.landlock_abi
        ));
    }
    Ok(())
}

/// A decoded name's alphabet: printable ASCII, and `…` (a compression
/// pointer) only at the end.
fn qname_chars_ok(name: &str) -> bool {
    let body = name.strip_suffix('…').unwrap_or(name);
    body.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// A DNS host name as nn-parse's `Sni::Host` gives it: ASCII lower case
/// letters, digits, hyphens and dots, at most 253 bytes, no empty label.
fn host_ok(h: &str) -> bool {
    !h.is_empty()
        && h.len() <= 253
        && h.split('.').all(|l| !l.is_empty() && l.len() <= 63)
        && h.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
}

fn lower_hex(b: &[u8], len: usize) -> bool {
    b.len() == len
        && b.iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

/// The bytes of `b` in `r`, or none (never a panic).
fn span(b: &[u8], r: core::ops::Range<usize>) -> &[u8] {
    b.get(r).unwrap_or(&[])
}

/// The byte of `b` at `i`, or 0 (never a panic).
fn at(b: &[u8], i: usize) -> u8 {
    b.get(i).copied().unwrap_or(0)
}

/// JA4 as nn-parse's `compute_ja4` writes it (36 bytes): `t` · the version
/// (`13`, `12`, `11`, `10`, `s3`, `s2`, `00`) · `d` or `i` · two digits ·
/// two digits · the ALPN pair (two ASCII bytes, any of them: the reference
/// implementations print the ends of the first ALPN value as they are) ·
/// `_` · 12 hex digits · `_` · 12 hex digits.
///
/// Bytes only (review of #480, F1): a `&str` sliced at 11 or 23 panics when
/// a lying worker puts a multi-byte character across that index.
fn ja4_ok(s: &str) -> bool {
    let b = s.as_bytes();
    s.is_ascii()
        && b.len() == 36
        && at(b, 0) == b't'
        && span(b, 1..3)
            .iter()
            .all(|x| x.is_ascii_digit() || *x == b's')
        && (at(b, 3) == b'd' || at(b, 3) == b'i')
        && span(b, 4..8).iter().all(u8::is_ascii_digit)
        && span(b, 8..10).len() == 2
        && at(b, 10) == b'_'
        && lower_hex(span(b, 11..23), 12)
        && at(b, 23) == b'_'
        && lower_hex(span(b, 24..36), 12)
}

/// The fewest bytes a DNS message with `a` A answers and `aaaa` AAAA
/// answers takes: its 12-byte header and each answer with a root name (one
/// byte), type, class, TTL, length and data (15 and 27 bytes).
pub const fn min_dns_answer_bytes(a: usize, aaaa: usize) -> usize {
    if a == 0 && aaaa == 0 {
        0
    } else {
        12 + 15 * a + 27 * aaaa
    }
}

/// The core's check of a response against the request it answers: the
/// answer's kind, its counts and sizes, its strings' alphabets.
pub fn check_response(req: &Request, answer: &Answer) -> Result<(), Violation> {
    match (req, answer) {
        // a closed set: nothing to bound
        (_, Answer::Refused(_)) => Ok(()),
        (Request::Ping, Answer::Pong) => Ok(()),
        (Request::DnsNames(ins), Answer::DnsNames(outs)) => {
            if ins.len() != outs.len() {
                return Err(Violation::Bounds("dns_names: one answer per name"));
            }
            for (i, o) in ins.iter().zip(outs) {
                if o.name.len() > max_qname_out(i.bytes.len()) {
                    return Err(Violation::Bounds("dns_names: name length"));
                }
                if !qname_chars_ok(&o.name) {
                    return Err(Violation::Bounds("dns_names: name characters"));
                }
                if i.form == QnameForm::Nss && o.name.ends_with('…') {
                    return Err(Violation::Bounds("dns_names: an NSS name has no pointer"));
                }
                match o.end {
                    None => {}
                    Some(_) if i.form != QnameForm::WireFindEnd => {
                        return Err(Violation::Bounds("dns_names: an end not asked for"))
                    }
                    Some(e) if usize::from(e) > i.bytes.len() || e == 0 => {
                        return Err(Violation::Bounds("dns_names: end past the bytes"))
                    }
                    Some(_) => {}
                }
            }
            Ok(())
        }
        (Request::TlsClientHello(_), Answer::Tls(t)) => match t {
            TlsOut::Incomplete | TlsOut::Invalid => Ok(()),
            TlsOut::Complete {
                ja3,
                ja4,
                sni,
                alpn,
            } => {
                if !lower_hex(ja3.as_bytes(), 32) {
                    return Err(Violation::Bounds("tls: ja3"));
                }
                if !ja4_ok(ja4) {
                    return Err(Violation::Bounds("tls: ja4"));
                }
                if let SniOut::Host(h) = sni {
                    if !host_ok(h) {
                        return Err(Violation::Bounds("tls: sni"));
                    }
                }
                if alpn.len() > MAX_ALPN
                    || alpn
                        .iter()
                        .any(|p| p.is_empty() || p.len() > MAX_TLS_FIELD || !printable_ascii(p))
                {
                    return Err(Violation::Bounds("tls: alpn"));
                }
                Ok(())
            }
        },
        (Request::DnsAnswers(bytes), Answer::DnsAnswers { a, aaaa }) => {
            if min_dns_answer_bytes(a.len(), aaaa.len()) > bytes.len() {
                return Err(Violation::Bounds("dns_answers: more answers than bytes"));
            }
            Ok(())
        }
        (req, _) => Err(Violation::WrongKind(req.name())),
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::string_slice)]
mod tests {
    use super::*;
    use alloc::vec;

    fn level() -> SandboxLevel {
        SandboxLevel {
            landlock_abi: 4,
            landlock: LandlockEnforced::Full,
            fs_denied: true,
            net_denied: true,
            scoped: false,
            seccomp: true,
            no_new_privs: true,
            dumpable: false,
            uid: 990,
            gid: 990,
            groups: 0,
            cap_bnd: 0x3ff,
            nofile: 8,
            ..SandboxLevel::default()
        }
    }

    fn hello() -> WorkerHello {
        WorkerHello {
            version: IPC_VERSION,
            kind: WorkerKind::Parse,
            pid: 4242,
            sandbox: level(),
        }
    }

    fn want() -> Expected {
        Expected {
            kind: WorkerKind::Parse,
            pid: 4242,
            uid: 990,
            gid: 990,
            kernel_landlock_abi: 4,
        }
    }

    #[test]
    fn a_conforming_hello_passes() {
        assert_eq!(check_hello(&hello(), &want()), Ok(()));
        // no Landlock at all, on a kernel without it, is declared, not
        // refused
        let mut h = hello();
        h.sandbox.landlock_abi = 0;
        h.sandbox.landlock = LandlockEnforced::None;
        h.sandbox.fs_denied = false;
        h.sandbox.net_denied = false;
        let w = Expected {
            kernel_landlock_abi: 0,
            ..want()
        };
        assert_eq!(check_hello(&h, &w), Ok(()));
    }

    #[test]
    fn every_weaker_hello_is_refused() {
        type Weaken = fn(&mut WorkerHello);
        let cases: Vec<(&str, Weaken)> = vec![
            ("version", |h| h.version += 1),
            ("pid", |h| h.pid += 1),
            ("uid", |h| h.sandbox.uid = 0),
            ("other uid", |h| h.sandbox.uid = 991),
            ("gid", |h| h.sandbox.gid = 0),
            ("groups", |h| h.sandbox.groups = 1),
            ("seccomp", |h| h.sandbox.seccomp = false),
            ("nnp", |h| h.sandbox.no_new_privs = false),
            ("dumpable", |h| h.sandbox.dumpable = true),
            ("cap_eff", |h| h.sandbox.cap_eff = 1),
            ("cap_prm", |h| h.sandbox.cap_prm = 1 << 21),
            ("cap_inh", |h| h.sandbox.cap_inh = 1),
            ("cap_amb", |h| h.sandbox.cap_amb = 1),
            ("core", |h| h.sandbox.core = 1),
            ("nproc", |h| h.sandbox.nproc = 1),
            ("landlock without abi", |h| {
                h.sandbox.landlock_abi = 0;
                h.sandbox.net_denied = false;
            }),
            ("net below abi 4", |h| h.sandbox.landlock_abi = 3),
            ("scope below abi 6", |h| h.sandbox.scoped = true),
        ];
        for (what, f) in cases {
            let mut h = hello();
            f(&mut h);
            assert!(
                matches!(check_hello(&h, &want()), Err(Violation::Hello(_))),
                "{what}"
            );
        }
        let mut w = want();
        w.kind = WorkerKind::Parse;
        w.uid = 991;
        assert!(check_hello(&hello(), &w).is_err());
    }

    /// Review of #480 (F7): the worker's Landlock is checked against the
    /// kernel's ABI as the core reads it — the same ABI, and the rights it
    /// gives measured as enforced; a right above the ABI is a lie.
    #[test]
    fn the_landlock_level_is_checked_against_the_kernel_s_abi() {
        let at = |kernel: u8, f: fn(&mut SandboxLevel)| {
            let mut h = hello();
            f(&mut h.sandbox);
            let w = Expected {
                kernel_landlock_abi: kernel,
                ..want()
            };
            check_hello(&h, &w)
        };
        assert_eq!(at(4, |_| {}), Ok(()));
        // a kernel without Landlock: nothing to measure
        assert_eq!(
            at(0, |l| {
                l.landlock_abi = 0;
                l.landlock = LandlockEnforced::None;
                l.fs_denied = false;
                l.net_denied = false;
            }),
            Ok(())
        );
        // ABI 6: the scope measured too
        assert_eq!(
            at(6, |l| {
                l.landlock_abi = 6;
                l.scoped = true;
            }),
            Ok(())
        );
        // a kernel above what the build knows: the build's newest
        assert_eq!(
            at(12, |l| {
                l.landlock_abi = LANDLOCK_ABI_KNOWN;
                l.scoped = true;
            }),
            Ok(())
        );
        type Weaken = fn(&mut SandboxLevel);
        let refused: Vec<(&str, u8, Weaken)> = vec![
            ("another ABI than the kernel's", 4, |l| l.landlock_abi = 2),
            ("no Landlock where the kernel has it", 4, |l| {
                l.landlock_abi = 4;
                l.landlock = LandlockEnforced::None;
            }),
            ("files not denied", 4, |l| l.fs_denied = false),
            ("TCP not denied from ABI 4", 4, |l| l.net_denied = false),
            ("no scope at ABI 6", 6, |l| l.landlock_abi = 6),
            ("TCP claimed at ABI 3", 3, |l| l.landlock_abi = 3),
            ("scope claimed at ABI 4", 4, |l| l.scoped = true),
            ("the build's ABI above the kernel's", 12, |l| {
                l.landlock_abi = 12
            }),
        ];
        for (what, kernel, f) in refused {
            assert!(matches!(at(kernel, f), Err(Violation::Hello(_))), "{what}");
        }
    }

    #[test]
    fn frames_are_bounded_and_whole() {
        let m = FromWorker::Hello(hello());
        let b = encode(&m).unwrap();
        assert_eq!(decode::<FromWorker>(&b).unwrap(), m);
        let mut trailing = b.clone();
        trailing.push(0);
        assert!(matches!(
            decode::<FromWorker>(&trailing),
            Err(Violation::Malformed(_))
        ));
        assert!(matches!(
            decode::<FromWorker>(&b[..b.len() - 1]),
            Err(Violation::Malformed(_))
        ));
        let big = vec![0u8; MAX_FRAME + 1];
        assert_eq!(
            decode::<FromWorker>(&big),
            Err(Violation::Oversized(MAX_FRAME + 1))
        );
        // a request whose encoding is above the frame is not sent
        let huge = ToWorker {
            id: 1,
            req: Request::DnsAnswers(vec![0; MAX_FRAME]),
        };
        assert!(encode(&huge).is_err());
        // the worst answer to a request the bounds allow fits a frame: every
        // name escaped byte by byte, and a pointer
        let n = (MAX_FRAME - FRAME_MARGIN) / worst_answer(MAX_QNAME_IN);
        let req = Request::DnsNames(vec![
            QnameIn {
                bytes: vec![0x01; MAX_QNAME_IN],
                form: QnameForm::Wire
            };
            n
        ]);
        assert!(req.check().is_ok());
        let worst = FromWorker::Response(Response {
            id: u64::MAX,
            answer: Answer::DnsNames(vec![
                QnameOut {
                    name: "\\001".repeat(MAX_QNAME_IN) + "…",
                    end: Some(u16::MAX)
                };
                n
            ]),
        });
        assert!(encode(&worst).is_ok(), "the worst answer fits");
        let mut over = req.clone();
        if let Request::DnsNames(v) = &mut over {
            v.push(QnameIn {
                bytes: vec![0x01; MAX_QNAME_IN],
                form: QnameForm::Wire,
            });
        }
        assert!(over.check().is_err(), "one more does not");
        // the largest request the bounds allow fits a frame
        let names = ToWorker {
            id: u64::MAX,
            req: Request::DnsNames(vec![
                QnameIn {
                    bytes: vec![0xff; 120],
                    form: QnameForm::WireFindEnd
                };
                MAX_BATCH
            ]),
        };
        assert!(encode(&names).unwrap().len() <= MAX_FRAME);
    }

    #[test]
    fn requests_out_of_bounds_are_refused() {
        assert!(Request::DnsNames(vec![]).check().is_err());
        assert!(Request::DnsNames(vec![
            QnameIn {
                bytes: vec![],
                form: QnameForm::Wire
            };
            MAX_BATCH + 1
        ])
        .check()
        .is_err());
        assert!(Request::DnsNames(vec![QnameIn {
            bytes: vec![1; MAX_QNAME_IN + 1],
            form: QnameForm::Wire
        }])
        .check()
        .is_err());
        assert!(Request::TlsClientHello(vec![0; MAX_TLS_IN + 1])
            .check()
            .is_err());
        assert!(Request::DnsAnswers(vec![0; MAX_DNS_ANSWER_IN + 1])
            .check()
            .is_err());
        assert!(Request::TlsClientHello(vec![0; MAX_TLS_IN]).check().is_ok());
        assert!(Request::Ping.check().is_ok());
    }

    fn q(bytes: &[u8], find_end: bool) -> QnameIn {
        QnameIn {
            bytes: bytes.to_vec(),
            form: if find_end {
                QnameForm::WireFindEnd
            } else {
                QnameForm::Wire
            },
        }
    }

    fn name(s: &str, end: Option<u16>) -> QnameOut {
        QnameOut {
            name: s.to_string(),
            end,
        }
    }

    #[test]
    fn qname_results_are_checked() {
        let req = Request::DnsNames(vec![q(b"\x03abc\x00\x00\x01", true), q(b"\x01a", false)]);
        let ok = Answer::DnsNames(vec![name("abc", Some(5)), name("a", None)]);
        assert_eq!(check_response(&req, &ok), Ok(()));
        let bad = |a: Answer| check_response(&req, &a);
        assert!(bad(Answer::DnsNames(vec![name("abc", Some(5))])).is_err());
        assert!(bad(Answer::DnsNames(vec![
            name("abc", Some(8)),
            name("a", None)
        ]))
        .is_err());
        assert!(bad(Answer::DnsNames(vec![
            name("abc", Some(0)),
            name("a", None)
        ]))
        .is_err());
        assert!(bad(Answer::DnsNames(vec![
            name("abc", None),
            name("a", Some(1))
        ]))
        .is_err());
        assert!(bad(Answer::DnsNames(vec![name("ab\nc", None), name("a", None)])).is_err());
        assert!(bad(Answer::DnsNames(vec![
            name("abc", None),
            name("a\u{7f}", None)
        ]))
        .is_err());
        assert!(bad(Answer::DnsNames(vec![name("…a", None), name("a", None)])).is_err());
        let long = "x".repeat(max_qname_out(2) + 1);
        assert!(bad(Answer::DnsNames(vec![name("abc", None), name(&long, None)])).is_err());
        // the longest decode of each input passes: every byte escaped, a pointer
        let req1 = Request::DnsNames(vec![q(b"\x02\x00\x01", false)]);
        let longest = "\\000\\001…";
        assert!(longest.len() <= max_qname_out(3));
        assert_eq!(
            check_response(&req1, &Answer::DnsNames(vec![name(longest, None)])),
            Ok(())
        );
        assert!(bad(Answer::Pong).is_err());
    }

    /// R14b: an NSS name is text: no pointer, no end.
    #[test]
    fn nss_results_are_checked() {
        let req = Request::DnsNames(vec![QnameIn {
            bytes: b"example.com".to_vec(),
            form: QnameForm::Nss,
        }]);
        let ok = Answer::DnsNames(vec![name("example.com", None)]);
        assert_eq!(check_response(&req, &ok), Ok(()));
        assert!(check_response(&req, &Answer::DnsNames(vec![name("a…", None)])).is_err());
        assert!(check_response(&req, &Answer::DnsNames(vec![name("a", Some(1))])).is_err());
    }

    #[test]
    fn tls_results_are_checked() {
        let req = Request::TlsClientHello(vec![0x16; 10]);
        let good = || TlsOut::Complete {
            ja3: "0123456789abcdef0123456789abcdef".into(),
            ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1".into(),
            sni: SniOut::Host("example.com".into()),
            alpn: vec!["h2".into(), "http/1.1".into()],
        };
        assert_eq!(check_response(&req, &Answer::Tls(good())), Ok(()));
        assert_eq!(check_response(&req, &Answer::Tls(TlsOut::Invalid)), Ok(()));
        let with = |f: fn(&mut TlsOut)| {
            let mut t = good();
            f(&mut t);
            check_response(&req, &Answer::Tls(t))
        };
        assert!(with(|t| if let TlsOut::Complete { ja3, .. } = t {
            *ja3 = "0123456789ABCDEF0123456789abcdef".into()
        })
        .is_err());
        assert!(with(|t| if let TlsOut::Complete { ja3, .. } = t {
            ja3.push('0')
        })
        .is_err());
        assert!(with(|t| if let TlsOut::Complete { ja4, .. } = t {
            *ja4 = "t13d1516h2_8daaf6152771".into()
        })
        .is_err());
        assert!(with(|t| if let TlsOut::Complete { ja4, .. } = t {
            *ja4 = "t13d1516h2_8daaf615277X_e5627efa2ab1".into()
        })
        .is_err());
        // the ALPN pair is any two ASCII bytes, `_` included
        assert!(with(|t| if let TlsOut::Complete { ja4, .. } = t {
            *ja4 = "t13d1516___8daaf6152771_e5627efa2ab1".into()
        })
        .is_ok());
        assert!(with(|t| if let TlsOut::Complete { ja4, .. } = t {
            *ja4 = "t13d1516h\u{7f}8daaf6152771_e5627efa2ab1".into()
        })
        .is_err());
        assert!(with(|t| if let TlsOut::Complete { ja4, .. } = t {
            *ja4 = "t13x1516h2_8daaf6152771_e5627efa2ab1".into()
        })
        .is_err());
        assert!(with(|t| if let TlsOut::Complete { sni, .. } = t {
            *sni = SniOut::Host("Example.com".into())
        })
        .is_err());
        assert!(with(|t| if let TlsOut::Complete { sni, .. } = t {
            *sni = SniOut::Host("a..b".into())
        })
        .is_err());
        assert!(with(|t| if let TlsOut::Complete { sni, .. } = t {
            *sni = SniOut::Host("x".repeat(254))
        })
        .is_err());
        assert!(with(|t| if let TlsOut::Complete { alpn, .. } = t {
            alpn.push(String::new())
        })
        .is_err());
        assert!(with(|t| if let TlsOut::Complete { alpn, .. } = t {
            *alpn = vec!["h2".into(); MAX_ALPN + 1]
        })
        .is_err());
        assert!(check_response(&req, &Answer::Pong).is_err());
    }

    #[test]
    fn dns_answer_results_are_checked() {
        let req = Request::DnsAnswers(vec![0; 69]);
        let ok = Answer::DnsAnswers {
            a: vec![[1, 2, 3, 4]; 2],
            aaaa: vec![[0; 16]],
        };
        assert_eq!(min_dns_answer_bytes(2, 1), 69);
        assert_eq!(check_response(&req, &ok), Ok(()));
        let too_many = Answer::DnsAnswers {
            a: vec![[1, 2, 3, 4]; 4],
            aaaa: vec![],
        };
        assert!(check_response(&req, &too_many).is_err());
        assert!(check_response(&req, &Answer::Pong).is_err());
        for r in [Refusal::OutOfBounds, Refusal::DebugOnly] {
            assert_eq!(check_response(&req, &Answer::Refused(r)), Ok(()));
        }
    }

    /// Review of #480 (F1, the reviewer's probe): a lying worker's JA4 with
    /// a two-byte character across byte 23 — a `&str` sliced there panicked
    /// (`end byte index 23 is not a char boundary`), and the release
    /// profile aborts on a panic: the agent died. Refused now, as any
    /// non-ASCII JA4, wherever the character sits.
    #[test]
    fn a_ja4_with_a_multibyte_character_is_refused_not_a_panic() {
        let req = Request::TlsClientHello(vec![0x16]);
        for at in 0..35 {
            let mut ja4: Vec<u8> = b"t13d1516h2_8daaf6152771_e5627efa2ab1".to_vec();
            ja4.truncate(at);
            let mut s = String::from_utf8(ja4).unwrap();
            s.push('é');
            while s.len() < 36 {
                s.push('a');
            }
            let ans = Answer::Tls(TlsOut::Complete {
                ja3: "0".repeat(32),
                ja4: s,
                sni: SniOut::Absent,
                alpn: vec![],
            });
            assert!(check_response(&req, &ans).is_err(), "at {at}");
        }
        // the reviewer's string, as given
        let mut ja4 = String::from("t13d1516h2_");
        ja4.push_str("aaaaaaaaaaa");
        ja4.push('é');
        ja4.push_str("aaaaaaaaaaaa");
        assert_eq!(ja4.len(), 36);
        let ans = Answer::Tls(TlsOut::Complete {
            ja3: "0".repeat(32),
            ja4,
            sni: SniOut::Absent,
            alpn: vec![],
        });
        assert!(check_response(&req, &ans).is_err());
        // a two-byte character as the ALPN pair, everything else in its
        // place: 36 bytes, refused for not being ASCII alone
        let ja4 = String::from("t13d1516é_8daaf6152771_e5627efa2ab1");
        assert_eq!(ja4.len(), 36);
        let ans = Answer::Tls(TlsOut::Complete {
            ja3: "0".repeat(32),
            ja4,
            sni: SniOut::Absent,
            alpn: vec![],
        });
        assert!(check_response(&req, &ans).is_err());
    }

    /// Review of #480 (F9): an ALPN name is printable ASCII as the worker
    /// hands it on; the core refuses anything else.
    #[test]
    fn alpn_names_are_printable_ascii() {
        assert_eq!(alpn_display(b"h2"), "h2");
        assert_eq!(alpn_display(b"a b"), "a b");
        assert_eq!(alpn_display(b"a\nb\\"), "a\\x0ab\\x5c");
        assert_eq!(alpn_display("é".as_bytes()), "\\xc3\\xa9");
        let long = alpn_display(&[0u8; 300]);
        assert_eq!(long.len(), MAX_TLS_FIELD - MAX_TLS_FIELD % 4);
        assert!(long.bytes().all(|b| (0x20..=0x7e).contains(&b)));
        assert_eq!(alpn_display(&[b'x'; 300]).len(), MAX_TLS_FIELD);
        let req = Request::TlsClientHello(vec![0x16]);
        let with_alpn = |a: &str| {
            check_response(
                &req,
                &Answer::Tls(TlsOut::Complete {
                    ja3: "0".repeat(32),
                    ja4: "t13d1516h2_8daaf6152771_e5627efa2ab1".into(),
                    sni: SniOut::Absent,
                    alpn: vec![a.into()],
                }),
            )
        };
        assert_eq!(with_alpn("http/1.1"), Ok(()));
        assert_eq!(with_alpn(&alpn_display(b"\x00\xff")), Ok(()));
        assert!(with_alpn("a\nb").is_err());
        assert!(with_alpn("é").is_err());
        assert!(with_alpn("\u{7f}").is_err());
    }

    #[test]
    fn kinds_have_names() {
        for k in WorkerKind::ALL {
            assert_eq!(WorkerKind::from_name(k.name()), Some(k));
        }
        assert_eq!(WorkerKind::from_name("export"), None);
        assert!(level().summary().contains("landlock abi 4 full (fs, net)"));
    }
}
