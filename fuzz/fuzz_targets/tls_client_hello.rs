#![no_main]
//! TLS ClientHello bytes come straight from the kernel ring buffer
//! (JA3/JA4 fingerprinting): attacker-controlled by construction. The
//! parse is not discarded (WDG-R08): on every hello it accepts,
//! - JA3's input keeps five comma-separated fields, the version first and
//!   one value per non-GREASE cipher and extension; JA3 is 32 hex digits;
//! - JA4 ends with two 12-hex-digit hashes after a 10-character prefix
//!   that starts with `t`;
//! - a record-wrapped hello parses as its handshake alone.
use libfuzzer_sys::fuzz_target;
use northnarrow_agent::net::tls_parser::{
    compute_ja3, compute_ja3_raw, compute_ja4, parse_client_hello,
};

fn is_grease(v: u16) -> bool {
    (v & 0x0F0F) == 0x0A0A
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

    if data[0] == 0x16 {
        assert_eq!(parse_client_hello(&data[5..]).as_ref(), Some(&hello));
    }
});
