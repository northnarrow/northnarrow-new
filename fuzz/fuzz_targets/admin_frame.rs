#![no_main]
//! Admin socket frames arrive from a local client that may be hostile
//! (a compromised root shell talks to the same socket): decoding any
//! byte sequence must never panic — reject, or ask for more bytes.
use libfuzzer_sys::fuzz_target;
use northnarrow_common::wire::admin_protocol::{decode_frame, decode_versioned_or_legacy_frame};

fuzz_target!(|data: &[u8]| {
    let _ = decode_versioned_or_legacy_frame(data);
    let _ = decode_frame(data);
});
