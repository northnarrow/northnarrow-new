#![no_main]
//! tracefs `format` files are parsed at boot to place the tracepoint
//! field offsets (RHEL 9 header shift). Beyond "never panics": an offset
//! is found only on a `field:` line that names the field, and it is
//! written there.
use libfuzzer_sys::fuzz_target;
use northnarrow_agent::anti_tamper::btf_revalidate::parse_format_field_offset;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for field in ["filename", "flags"] {
        if let Some(offset) = parse_format_field_offset(text, field) {
            let digits = offset.to_string();
            assert!(
                text.lines().any(|l| {
                    let l = l.trim();
                    l.starts_with("field:") && l.contains(field) && l.contains(digits.as_str())
                }),
                "{field} at {offset}: no field line says so"
            );
        }
    }
});
