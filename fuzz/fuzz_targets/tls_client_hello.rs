#![no_main]
//! TLS ClientHello bytes come straight from the kernel ring buffer
//! (JA3 fingerprinting): attacker-controlled by construction.
use libfuzzer_sys::fuzz_target;
use northnarrow_agent::net::tls_parser::parse_client_hello;

fuzz_target!(|data: &[u8]| {
    let _ = parse_client_hello(data);
});
