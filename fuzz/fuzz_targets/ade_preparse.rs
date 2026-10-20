#![no_main]
//! The ADE pre-parser (WDG-R04): what the verdict parser cuts from the
//! model's text before serde sees it — the reasoning block, code fences,
//! the prose around the first balanced object. Beyond "never panics":
//! - the text it keeps is a slice of the input;
//! - it fails only on a reasoning block opened and never closed;
//! - a balanced object it finds starts with `{`, ends with `}`, and is
//!   found again whole in itself (the brace and string scan is stable).
use libfuzzer_sys::fuzz_target;
use northnarrow_agent::fuzz_api::{ade_first_json_object, ade_preparse};

fn is_slice_of(part: &str, whole: &str) -> bool {
    let (p, w) = (part.as_ptr() as usize, whole.as_ptr() as usize);
    p >= w && p + part.len() <= w + whole.len()
}

fuzz_target!(|data: &[u8]| {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };
    match ade_preparse(raw) {
        Ok(kept) => assert!(is_slice_of(kept, raw)),
        Err(_) => {
            let open = raw
                .find("<think>")
                .expect("an error without a reasoning block");
            assert!(!raw[open..].contains("</think>"), "a closed block refused");
        }
    }
    if let Some(obj) = ade_first_json_object(raw) {
        assert!(is_slice_of(obj, raw));
        assert!(obj.starts_with('{') && obj.ends_with('}'), "{obj:?}");
        assert_eq!(ade_first_json_object(obj), Some(obj));
    }
});
