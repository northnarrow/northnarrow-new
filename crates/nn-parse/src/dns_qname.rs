//! DNS names on the wire (RFC 1035 §3.1): the allocation-free label walk
//! [`QnameLabels`], the decoder built on it ([`decode_dns_qname`]) and the
//! end of a name in a wire buffer ([`qname_wire_end`]).
//!
//! The bytes are copied by the kernel from a process's DNS query: written
//! by whoever runs on the host. The walk is model-checked (`kani_proofs`
//! below) and fuzzed (`fuzz/fuzz_targets/dns_records.rs`). It lived in
//! `model.rs` until external audit SUP-023 (NN-AUD-407): the Kani workflow
//! runs on the pull requests that touch this file, and the event model,
//! changed often, no longer starts it.

use alloc::string::String;

/// Decode a DNS label-encoded QNAME (RFC 1035 §3.1) into dotted form.
///
/// Only handles uncompressed names — a compression pointer (high bits
/// `0b11_xx_xxxx`) terminates decoding and the partial result is
/// returned with a trailing `…`. Compression doesn't appear in
/// outbound queries from glibc/getaddrinfo, so this is fine for
/// Tappa 4 telemetry.
///
/// External audit NN-AUD-185: a label may hold any byte, `.` included.
/// Copied verbatim, one label read as several (the label `a.b` as the
/// labels `a` and `b`, a whole well-known host name in one label), and
/// every unprintable byte became the same `?`. Distinct names on the wire
/// now decode to distinct strings, in the presentation form of RFC 4343
/// §2.1: `.` inside a label is `\046`, `\` is `\092`, a byte outside
/// printable ASCII is `\DDD` (decimal). Numeric, not `\.`: the consumers
/// split on `.`. Ordinary names are unchanged.
pub fn decode_dns_qname(buf: &[u8]) -> String {
    let mut out = String::new();
    for label in QnameLabels::new(buf) {
        match label {
            QnameLabel::Pointer => out.push('…'),
            QnameLabel::Data(bytes) => {
                if !out.is_empty() {
                    out.push('.');
                }
                for &b in bytes {
                    if (32..=126).contains(&b) && b != b'.' && b != b'\\' {
                        out.push(b as char);
                    } else {
                        out.push_str(&format!("\\{b:03}"));
                    }
                }
            }
        }
    }
    out
}

/// One label of a DNS label-encoded name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QnameLabel<'a> {
    /// Label bytes (possibly cut short by the end of the buffer).
    Data(&'a [u8]),
    /// A compression pointer: decoding stops here.
    Pointer,
}

/// Allocation-free walk over the labels of a DNS name — the index
/// arithmetic of [`decode_dns_qname`], separated from the string building
/// so it can be model-checked (Kani, Tappa 10.8). Stops at the root label,
/// at a compression pointer, or at the end of the buffer.
pub struct QnameLabels<'a> {
    buf: &'a [u8],
    i: usize,
    done: bool,
}

impl<'a> QnameLabels<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            i: 0,
            done: false,
        }
    }
}

impl<'a> Iterator for QnameLabels<'a> {
    type Item = QnameLabel<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.i >= self.buf.len() {
            return None;
        }
        let len = self.buf[self.i] as usize;
        if len == 0 {
            self.done = true;
            return None;
        }
        if len & 0xC0 != 0 {
            // compression pointer — give up cleanly
            self.done = true;
            return Some(QnameLabel::Pointer);
        }
        let start = self.i + 1;
        let end = core::cmp::min(start + len, self.buf.len());
        let label = &self.buf[start..end];
        if end == self.buf.len() {
            self.done = true;
        }
        self.i = end;
        Some(QnameLabel::Data(label))
    }
}

/// Where a name ends in a wire buffer: the index just past its root label.
/// `None` when the buffer ends first (the name continues past what was
/// read) or a compression pointer stops the walk (a query's own name never
/// needs one). Tappa 10.9 step 3: the type follows at this index.
pub fn qname_wire_end(buf: &[u8]) -> Option<usize> {
    let mut labels = QnameLabels::new(buf);
    for label in labels.by_ref() {
        if label == QnameLabel::Pointer {
            return None;
        }
    }
    // The walk stopped at a root label (inside the buffer) or at its end.
    (labels.i < buf.len() && buf[labels.i] == 0).then_some(labels.i + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// External audit NN-AUD-185: a `.` inside a label is not a separator —
    /// the consumers that split on `.` see one long label, as on the wire.
    #[test]
    fn decode_escapes_dot_inside_label() {
        let buf = b"\x18aaaa.bbbb.cccc.dddd.eeee\x07example\x03com\x00";
        let name = decode_dns_qname(buf);
        assert_eq!(name, "aaaa\\046bbbb\\046cccc\\046dddd\\046eeee.example.com");
        let first = name.split('.').next().unwrap();
        assert!(first.len() >= 20, "{first}");
        assert_eq!(name.split('.').count(), 3);
        // one label spelling a well-known host does not read as that host
        let spoof = decode_dns_qname(b"\x0dlogin.bank.io\x08attacker\x03net\x00");
        assert_eq!(spoof, "login\\046bank\\046io.attacker.net");
        assert!(!spoof.starts_with("login.bank.io"));
    }

    /// External audit NN-AUD-185: distinct wire names decode to distinct
    /// strings — dots, backslashes and unprintable bytes inside labels
    /// included (every name of up to two labels of one or two bytes over
    /// an alphabet of such bytes).
    #[test]
    fn distinct_wire_names_decode_distinct() {
        assert_ne!(
            decode_dns_qname(b"\x03a.b\x03com\x00"),
            decode_dns_qname(b"\x01a\x01b\x03com\x00")
        );
        assert_ne!(
            decode_dns_qname(b"\x02a\x01\x00"),
            decode_dns_qname(b"\x02a\x02\x00")
        );
        assert_ne!(
            decode_dns_qname(b"\x05a\\046\x00"),
            decode_dns_qname(b"\x02a.\x00")
        );
        let alphabet = [b'a', b'.', b'\\', b'0', b'4', 0x01, 0x7f, 0xff];
        let mut labels: Vec<Vec<u8>> = alphabet.iter().map(|&b| vec![b]).collect();
        for &x in &alphabet {
            for &y in &alphabet {
                labels.push(vec![x, y]);
            }
        }
        let mut seen = std::collections::HashMap::new();
        let mut names: Vec<Vec<Vec<u8>>> = labels.iter().map(|l| vec![l.clone()]).collect();
        for a in &labels {
            for b in &labels {
                names.push(vec![a.clone(), b.clone()]);
            }
        }
        for name in names {
            let mut wire = Vec::new();
            for l in &name {
                wire.push(l.len() as u8);
                wire.extend_from_slice(l);
            }
            wire.push(0);
            let decoded = decode_dns_qname(&wire);
            if let Some(other) = seen.insert(decoded.clone(), name.clone()) {
                panic!("{name:?} and {other:?} both decode to {decoded:?}");
            }
        }
    }

    /// External audit NN-AUD-185: the escapes touch only what a stub
    /// resolver never sends.
    #[test]
    fn ordinary_names_unchanged() {
        for (wire, name) in [
            (&b"\x03www\x07example\x03com\x00"[..], "www.example.com"),
            (
                b"\x04_sip\x04_tcp\x07example\x03org\x00",
                "_sip._tcp.example.org",
            ),
            (b"\x0dxn--bcher-kva\x07example\x00", "xn--bcher-kva.example"),
            (b"\x03a-b\x03c_d\x01e\x00", "a-b.c_d.e"),
            (
                b"\x011\x010\x03168\x03192\x07in-addr\x04arpa\x00",
                "1.0.168.192.in-addr.arpa",
            ),
            (b"\x07example\x03com", "example.com"),
        ] {
            assert_eq!(decode_dns_qname(wire), name);
        }
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
    fn qname_wire_end_finds_the_root_label() {
        assert_eq!(qname_wire_end(b"\x01a\x00\x00\x01"), Some(3));
        assert_eq!(qname_wire_end(b"\x00"), Some(1)); // the root name
        assert_eq!(qname_wire_end(b"\x01a"), None);
        assert_eq!(qname_wire_end(b""), None);
        assert_eq!(qname_wire_end(b"\x05ab"), None); // label cut by the end
    }

    /// External audit WDG-R07 (NN-AUD-373): the audit's hostile shapes. The
    /// walk never follows a compression pointer, so a pointer to itself or
    /// a chain of them ends it at once; a label announced past the end of
    /// the buffer is cut there; a name that never reaches its root label
    /// ends with the buffer. Each terminates within `len` steps.
    #[test]
    fn hostile_names_terminate_in_bounds() {
        // a pointer to itself, and a name before one
        assert_eq!(decode_dns_qname(b"\xc0\x00"), "…");
        assert_eq!(decode_dns_qname(b"\x02ns\xc0\x02"), "ns…");
        assert_eq!(qname_wire_end(b"\xc0\x00"), None);
        // 128 pointers, each to the one before it
        let mut chain = b"\x01a".to_vec();
        for i in 0..128u16 {
            let at = 2 + 2 * i.saturating_sub(1);
            chain.extend_from_slice(&(0xC000 | at).to_be_bytes());
        }
        assert_eq!(decode_dns_qname(&chain), "a…");
        assert_eq!(QnameLabels::new(&chain).count(), 2);
        assert_eq!(qname_wire_end(&chain), None);
        // a label announced past the end of the buffer
        assert_eq!(decode_dns_qname(b"\x3fabc"), "abc");
        assert_eq!(decode_dns_qname(b"\x05"), "");
        assert_eq!(qname_wire_end(b"\x3fabc"), None);
        // 255 bytes of labels and no root label
        let mut long = b"\x01a".repeat(127);
        long.push(1);
        assert_eq!(long.len(), 255);
        let name = decode_dns_qname(&long);
        assert_eq!(name, format!("{}.", ["a"; 127].join(".")));
        assert_eq!(QnameLabels::new(&long).count(), 128);
        assert_eq!(qname_wire_end(&long), None);
        for buf in [&b"\xc0\x00"[..], &chain, b"\x3fabc", &long] {
            assert!(QnameLabels::new(buf).count() <= buf.len());
        }
    }
}

/// Kani proofs (Tappa 10.8, "verifica formale dopo il fuzzing"): the
/// decoders that turn kernel-written bytes into events never panic, for
/// every possible input of the bounded size — fuzzing samples the input
/// space, these cover all of it.
#[cfg(kani)]
mod kani_proofs {
    use super::*;

    const N: usize = 16;

    /// The label walk behind `decode_dns_qname` (kernel-copied, attacker-
    /// written bytes) on any buffer of up to 16 bytes: no out-of-bounds
    /// index, every label inside the buffer, and it terminates — each step
    /// consumes at least one byte, so there are at most `len` labels.
    #[kani::proof]
    #[kani::unwind(18)]
    fn qname_label_walk_is_in_bounds_and_terminates() {
        let backing: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let buf = &backing[..len];
        let mut steps = 0usize;
        for label in QnameLabels::new(buf) {
            if let QnameLabel::Data(bytes) = label {
                assert!(bytes.len() <= len);
            }
            steps += 1;
            assert!(steps <= len);
        }
    }

    /// `qname_wire_end` on any buffer of up to 16 bytes: the end it reports
    /// is inside the buffer and just past a root label, so the type read
    /// after it (`From<&DnsQueryRaw>`) starts in bounds.
    #[kani::proof]
    #[kani::unwind(18)]
    fn qname_wire_end_is_past_a_root_label() {
        let backing: [u8; N] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= N);
        let buf = &backing[..len];
        if let Some(end) = qname_wire_end(buf) {
            assert!(end >= 1 && end <= len);
            assert!(buf[end - 1] == 0);
        }
    }
}
