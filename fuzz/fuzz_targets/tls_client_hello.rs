#![no_main]
//! TLS ClientHello bytes come straight from the kernel ring buffer
//! (JA3/JA4 fingerprinting): attacker-controlled by construction. The
//! parse is not discarded (WDG-R08): on every hello it accepts,
//! - JA3's input keeps five comma-separated fields, the version first and
//!   one value per non-GREASE cipher and extension; JA3 is 32 hex digits;
//! - JA4 ends with two 12-hex-digit hashes after a 10-character prefix
//!   that starts with `t`;
//! - a hello inside one record parses as that record's fragment alone.
use libfuzzer_sys::fuzz_target;
use northnarrow_agent::net::tls_parser::{
    compute_ja3, compute_ja3_raw, compute_ja4, parse_client_hello,
};

/// RFC 8701 §2: the sixteen values 0x0A0A, 0x1A1A, …, 0xFAFA (both bytes
/// equal, low nibble A), written out here rather than taken from the parser.
fn is_grease(v: u16) -> bool {
    (v & 0x0F0F) == 0x0A0A && (v >> 8) == (v & 0xFF)
}

fn count(field: &str) -> usize {
    if field.is_empty() {
        0
    } else {
        field.split('-').count()
    }
}

fuzz_target!(|data: &[u8]| {
    let Some(hello) = parse_client_hello(data) else {
        return;
    };
    let raw = compute_ja3_raw(&hello);
    let fields: Vec<&str> = raw.split(',').collect();
    assert_eq!(fields.len(), 5, "{raw}");
    assert_eq!(fields[0], hello.version.to_string());
    let ciphers = hello
        .cipher_suites
        .iter()
        .filter(|c| !is_grease(**c))
        .count();
    let exts = hello
        .extensions
        .iter()
        .filter(|e| !is_grease(e.ext_type))
        .count();
    assert_eq!(
        (count(fields[1]), count(fields[2])),
        (ciphers, exts),
        "{raw}"
    );
    let ja3 = compute_ja3(&hello);
    assert!(
        ja3.len() == 32 && ja3.bytes().all(|b| b.is_ascii_hexdigit()),
        "{ja3}"
    );

    let ja4 = compute_ja4(&hello);
    let parts: Vec<&str> = ja4.rsplitn(3, '_').collect();
    assert_eq!(parts.len(), 3, "{ja4}");
    for hash in &parts[..2] {
        assert!(
            hash.len() == 12 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
            "{ja4}"
        );
    }
    assert!(
        parts[2].starts_with('t') && parts[2].chars().count() == 10,
        "{ja4}"
    );

    // One record holding the whole message: the record's fragment alone
    // parses the same. A message split over records is joined from their
    // fragments, so the bytes after the first header are not the message.
    if data[0] == 0x16 && data.len() >= 9 {
        let record_len = usize::from(u16::from_be_bytes([data[3], data[4]]));
        let message_len =
            4 + (usize::from(data[6]) << 16 | usize::from(data[7]) << 8 | usize::from(data[8]));
        if message_len <= record_len {
            let fragment = &data[5..data.len().min(5 + record_len)];
            assert_eq!(parse_client_hello(fragment).as_ref(), Some(&hello));
        }
    }
});
