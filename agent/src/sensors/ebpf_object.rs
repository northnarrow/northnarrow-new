//! The embedded eBPF object — single source of truth + boot preflight.
//!
//! `agent/build.rs` stages the compiled `.o` into `OUT_DIR` and, when
//! it does, records two facts about it as compile-time env:
//!   * `NN_EBPF_EMBEDDED` — `"1"` if a real, **staleness-verified**
//!     object was embedded, `"0"` if only the empty placeholder is
//!     present (a userland-only `cargo build` with no eBPF toolchain).
//!   * `NN_EBPF_OBJECT_SHA` — SHA-256 of the exact embedded bytes.
//!   * `NN_EBPF_BUILD_HASH` — the eBPF source-closure provenance hash
//!     the object was built from (for the auditable boot log line).
//!
//! Embedding the object in ONE place (rather than the two historical
//! `include_bytes_aligned!` copies in `exec.rs` + `multiplexer.rs`)
//! removes the chance of the two loaders ever disagreeing about which
//! bytes they load.
//!
//! [`preflight`] is the runtime half of the staleness guard: the build
//! refuses to embed a *stale* object, and this refuses to *start* on an
//! *absent* (placeholder) or *corrupted* one. Either way the agent
//! never runs against a kernel half that does not match its userland.

use anyhow::{bail, Result};
use aya::include_bytes_aligned;
use sha2::{Digest, Sha256};
use tracing::info;

/// Compiled eBPF object, staged into `OUT_DIR` by `agent/build.rs`.
///
/// `include_bytes_aligned!` wraps the bytes in a `#[repr(align(32))]`
/// struct: aya's ELF parser does pointer-aligned reads internally and
/// fails with "error parsing ELF data" if it gets a 1-byte-aligned
/// slice (which is what `core::include_bytes!` produces).
pub static EBPF_BYTES: &[u8] =
    include_bytes_aligned!(concat!(env!("OUT_DIR"), "/northnarrow-agent-ebpf"));

/// `"1"` iff `build.rs` embedded a real, staleness-verified object.
const EMBEDDED: &str = env!("NN_EBPF_EMBEDDED");
/// SHA-256 (hex) of the embedded object bytes, as recorded at build.
const OBJECT_SHA: &str = env!("NN_EBPF_OBJECT_SHA");
/// eBPF source-closure provenance hash the object was built from.
const BUILD_HASH: &str = env!("NN_EBPF_BUILD_HASH");

/// Boot-time self-check proving the embedded eBPF half is real and
/// intact before any sensor tries to load it. Call this once, early in
/// `main`, and abort on error — running without a matching kernel half
/// would silently disable every sensor, the anti-tamper LSM hooks, and
/// R011's non-forgeable PF_KTHREAD signal.
///
/// Refuses (fail-secure) when:
///   1. no real object was embedded (`NN_EBPF_EMBEDDED != "1"` or empty
///      bytes) — i.e. the binary was built without `cargo xtask build`;
///   2. the embedded bytes do not match the SHA `build.rs` recorded for
///      them — i.e. the object was corrupted or swapped after the
///      build-time staleness guard verified it.
///
/// On success it logs the auditable binding (object SHA + source
/// provenance) so every boot records, in the journal, exactly which
/// kernel half this agent is running.
pub fn preflight() -> Result<()> {
    if EMBEDDED != "1" || EBPF_BYTES.is_empty() {
        bail!(
            "eBPF object not embedded (NN_EBPF_EMBEDDED={EMBEDDED}, {} bytes): this agent \
             binary was built WITHOUT a freshly-compiled eBPF object. Rebuild with \
             `cargo xtask build --release` and reinstall. Refusing to start — running \
             without the kernel half would silently disable every sensor, the anti-tamper \
             LSM hooks, and R011's PF_KTHREAD signal.",
            EBPF_BYTES.len()
        );
    }

    let actual = hex::encode(Sha256::digest(EBPF_BYTES));
    if actual != OBJECT_SHA {
        bail!(
            "embedded eBPF object failed integrity check: expected sha256 {OBJECT_SHA}, got \
             {actual} ({} bytes). The object was corrupted or replaced after the build-time \
             staleness guard verified it. Refusing to start (fail-secure).",
            EBPF_BYTES.len()
        );
    }

    info!(
        object_sha = %OBJECT_SHA,
        build_hash = %BUILD_HASH,
        bytes = EBPF_BYTES.len(),
        "eBPF object preflight OK — embedded kernel half verified against build provenance"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The preflight verdict must agree with what `build.rs` baked in.
    /// Works in both environments: a normal local build embeds a real
    /// (stamped) object → `EMBEDDED == "1"` → preflight passes and the
    /// recorded SHA must match the bytes; a userland-only CI/IDE build
    /// embeds the placeholder → `EMBEDDED == "0"` → preflight refuses.
    #[test]
    fn preflight_decision_matches_build_env() {
        let r = preflight();
        if EMBEDDED == "1" {
            assert!(r.is_ok(), "an embedded build must pass preflight: {r:?}");
            assert!(!OBJECT_SHA.is_empty(), "embedded build must record a SHA");
            assert_eq!(
                hex::encode(Sha256::digest(EBPF_BYTES)),
                OBJECT_SHA,
                "recorded SHA must match the embedded bytes"
            );
            assert!(!EBPF_BYTES.is_empty());
        } else {
            assert!(
                r.is_err(),
                "a placeholder build (NN_EBPF_EMBEDDED=0) must refuse to start"
            );
        }
    }
}
