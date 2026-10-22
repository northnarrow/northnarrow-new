#![no_main]
//! DNS bytes from the wire and from the kernel's copy of a query
//! (attacker-written: any process sends its own). Beyond "never panics":
//! - the answers parsed from a response fit in it (an A answer takes at
//!   least 15 bytes after the 12-byte header, an AAAA one 27);
//! - `decode_dns_qname` (WDG-R07): printable ASCII only, a `…` only at
//!   the end and only for a compression pointer, and the name reads back
//!   as the wire labels: unescaping the RFC 4343 `\DDD` form and splitting
//!   on `.` gives every label byte for byte, so distinct names on the
//!   wire never decode alike (NN-AUD-185);
//! - `qname_wire_end` reports an end inside the buffer, just past a root
//!   label (the Kani property, on buffers longer than the proof's).
use libfuzzer_sys::fuzz_target;
use northnarrow_agent::net::dns_cache::{parse_a_records, parse_aaaa_records};
use nn_parse::dns_qname::{QnameLabel, QnameLabels, decode_dns_qname, qname_wire_end};

/// The labels a decoded name spells, `\DDD` turned back into bytes.
fn read_back(name: &str) -> Vec<Vec<u8>> {
    name.split('.')
        .map(|label| {
            let b = label.as_bytes();
            let mut out = Vec::new();
            let mut i = 0;
            while i < b.len() {
                if b[i] == b'\\' {
                    let digits = b.get(i + 1..i + 4).expect("a \\DDD escape");
                    let digits = std::str::from_utf8(digits).expect("three digits");
                    out.push(digits.parse::<u8>().expect("a byte value"));
                    i += 4;
                } else {
                    out.push(b[i]);
                    i += 1;
                }
            }
            out
        })
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let a = parse_a_records(data);
    let aaaa = parse_aaaa_records(data);
    if !a.is_empty() || !aaaa.is_empty() {
        assert!(12 + 15 * a.len() + 27 * aaaa.len() <= data.len());
    }

    let name = decode_dns_qname(data);
    let mut labels = Vec::new();
    let mut pointer = false;
    for label in QnameLabels::new(data) {
        match label {
            QnameLabel::Data(bytes) => labels.push(bytes.to_vec()),
            QnameLabel::Pointer => pointer = true,
        }
    }
    let body = if pointer {
        name.strip_suffix('…')
            .expect("a pointer ends the name with …")
    } else {
        name.as_str()
    };
    assert!(
        body.bytes().all(|b| (32..=126).contains(&b)),
        "{name:?}: not printable ASCII"
    );
    if body.is_empty() {
        assert!(
            labels.iter().all(|l| l.is_empty()) && labels.len() <= 1,
            "{labels:?}"
        );
    } else {
        assert_eq!(read_back(body), labels, "{name:?}");
    }

    if let Some(end) = qname_wire_end(data) {
        assert!(end >= 1 && end <= data.len());
        assert_eq!(data[end - 1], 0);
    }
});
