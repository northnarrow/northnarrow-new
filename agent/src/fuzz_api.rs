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

/// COMBAT management carve-out splice: the generated ACCEPT block into an
/// operator `combat-rules.v4`/`.v6` body (marker line, else before the
/// first DROP, else before COMMIT).
#[doc(hidden)]
pub fn combat_splice_carveout(base: &str, accept_block: &str) -> String {
    crate::anti_tamper::network_isolate::splice_carveout(base, accept_block)
}

/// The marker line [`combat_splice_carveout`] replaces.
#[doc(hidden)]
pub const COMBAT_CARVE_OUT_MARKER: &str = crate::anti_tamper::network_isolate::CARVE_OUT_MARKER;
