#![no_main]
//! Role lists come from admin.pub and from the nn-admin CLI. Beyond "never
//! panics": a list that parses is not empty, names each role once, and
//! holds exactly the roles of its comma-separated keywords; a keyword that
//! parses is the one-role list of itself.
use libfuzzer_sys::fuzz_target;
use northnarrow_agent::anti_tamper::admin_auth::{parse_role_keyword, parse_role_list};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(roles) = parse_role_list(text) {
        assert!(!roles.is_empty());
        for (i, r) in roles.iter().enumerate() {
            assert!(!roles[..i].contains(r), "{r:?} twice in {roles:?}");
        }
        for token in text.split(',') {
            let role = parse_role_keyword(token).expect("every keyword of a parsed list");
            assert!(roles.contains(&role), "{token:?} parsed, dropped");
        }
    }
    if let Ok(role) = parse_role_keyword(text) {
        assert_eq!(parse_role_list(text).ok(), Some(vec![role]));
    }
});
