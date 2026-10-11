#![no_main]
//! tracefs `format` files are parsed at boot to place the tracepoint
//! field offsets (RHEL 9 header shift).
use libfuzzer_sys::fuzz_target;
use northnarrow_agent::anti_tamper::btf_revalidate::parse_format_field_offset;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = parse_format_field_offset(text, "filename");
        let _ = parse_format_field_offset(text, "flags");
    }
});
