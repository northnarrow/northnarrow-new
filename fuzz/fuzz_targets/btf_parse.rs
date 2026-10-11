#![no_main]
//! The agent's own BTF parser reads /sys/kernel/btf/vmlinux (and any blob
//! given to --btf-check): a malformed blob must be refused, never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = northnarrow_agent::fuzz_api::parse_btf_and_resolve(data);
});
