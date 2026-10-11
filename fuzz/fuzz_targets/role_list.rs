#![no_main]
//! Role lists come from admin.pub and from the nn-admin CLI.
use libfuzzer_sys::fuzz_target;
use northnarrow_agent::anti_tamper::admin_auth::{parse_role_keyword, parse_role_list};

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = parse_role_list(text);
        let _ = parse_role_keyword(text);
    }
});
