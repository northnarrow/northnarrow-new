#![no_main]
//! Chain-log lines are re-read at boot and by `nn-admin audit verify`;
//! a tampered or truncated line must be reported, never crash the reader.
//! A terminator hash comes only from a JSON object that carries `rotate`
//! and holds that `entry_hash`: a data line never links two archives.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Some(hash) = northnarrow_agent::fuzz_api::chainlog_terminator_entry_hash(text) {
            let v: serde_json::Value = serde_json::from_str(text).expect("a terminator is JSON");
            assert!(v.get("rotate").is_some(), "a terminator without `rotate`");
            assert_eq!(
                v.get("entry_hash").and_then(|h| h.as_str()),
                Some(hash.as_str())
            );
        }
    }
});
