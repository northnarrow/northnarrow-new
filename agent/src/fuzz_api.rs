//! Thin, `#[doc(hidden)]` wrappers over private parsers so the
//! `fuzz/` crate (cargo-fuzz, libFuzzer) can drive them without making
//! the internals public. Each wrapper must never panic on any input:
//! that is the property the fuzz targets assert. Not part of the
//! supported API.

/// Parse a BTF blob and resolve every offset/enumerator the agent needs.
/// Returns whether the blob parsed; the resolution outcome is discarded.
#[doc(hidden)]
pub fn parse_btf_and_resolve(data: &[u8]) -> bool {
    crate::anti_tamper::btf_revalidate::fuzz_parse_and_resolve(data)
}

/// Chain-log terminator line parser (JSON line → entry hash).
#[doc(hidden)]
pub fn chainlog_terminator_entry_hash(line: &str) -> Option<String> {
    crate::chainlog::fuzz_terminator_entry_hash(line)
}
