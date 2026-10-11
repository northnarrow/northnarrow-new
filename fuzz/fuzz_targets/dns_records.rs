#![no_main]
//! DNS response payloads observed on the wire.
use libfuzzer_sys::fuzz_target;
use northnarrow_agent::net::dns_cache::{parse_a_records, parse_aaaa_records};

fuzz_target!(|data: &[u8]| {
    let _ = parse_a_records(data);
    let _ = parse_aaaa_records(data);
});
