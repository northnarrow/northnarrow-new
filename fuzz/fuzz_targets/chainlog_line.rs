#![no_main]
//! Chain-log lines are re-read at boot and by `nn-admin audit verify`;
//! a tampered or truncated line must be reported, never crash the reader.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = northnarrow_agent::fuzz_api::chainlog_terminator_entry_hash(text);
    }
});
