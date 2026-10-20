#![no_main]
//! The agent's own BTF parser reads /sys/kernel/btf/vmlinux (and any blob
//! given to --btf-check): a malformed blob must be refused, never panic,
//! and a blob it accepts carries the BTF magic (either byte order) and the
//! whole 24-byte header.
use libfuzzer_sys::fuzz_target;

const BTF_MAGIC: u16 = 0xEB9F;

fuzz_target!(|data: &[u8]| {
    if northnarrow_agent::fuzz_api::parse_btf_and_resolve(data) {
        assert!(data.len() >= 24, "accepted without its header");
        assert!(
            u16::from_le_bytes([data[0], data[1]]) == BTF_MAGIC
                || u16::from_be_bytes([data[0], data[1]]) == BTF_MAGIC,
            "accepted without the BTF magic"
        );
    }
});
