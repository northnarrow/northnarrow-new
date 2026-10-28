//! The embedded eBPF object — single source of truth + boot preflight.
//!
//! nn-linux's `build.rs` (the agent's until R09b, lab PR 254) stages the
//! compiled `.o` into `OUT_DIR` and, when
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

/// Compiled eBPF object, staged into `OUT_DIR` by nn-linux's `build.rs`.
///
/// `include_bytes_aligned!` wraps the bytes in a `#[repr(align(32))]`
/// struct: aya's ELF parser does pointer-aligned reads internally and
/// fails with "error parsing ELF data" if it gets a 1-byte-aligned
/// slice (which is what `core::include_bytes!` produces).
///
/// Wave 4 restructure, R11b (lab PR 262): this crate's alone. Its loaders
/// take the start's [`crate::boot::IntegrityVerified`]
/// ([`crate::sensors::SensorMultiplexer::start_with_net`],
/// [`crate::sensors::ExecSensor::start`]); the lab builds' one-shot modes
/// (`--sensor-feasibility`, `--verifier-check`) load it under a pin
/// directory of their own and exit before any start.
pub(crate) static EBPF_BYTES: &[u8] =
    include_bytes_aligned!(concat!(env!("OUT_DIR"), "/northnarrow-agent-ebpf"));

/// `"1"` iff `build.rs` embedded a real, staleness-verified object.
const EMBEDDED: &str = env!("NN_EBPF_EMBEDDED");
/// SHA-256 (hex) of the embedded object bytes, as recorded at build.
/// SHA-256 (hex) of the embedded eBPF object — compared with the install
/// manifest at boot (the agent's `install_manifest`).
pub const OBJECT_SHA: &str = env!("NN_EBPF_OBJECT_SHA");
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

    /// Set where the eBPF object was built: [`every_map_is_one_the_agents_aya_loads`]
    /// fails on a build that embeds none.
    const REQUIRE_OBJECT_ENV: &str = "NN_REQUIRE_EBPF_OBJECT";

    /// The map types aya 0.14.0's loader turns into a `Map` it can hand
    /// out: `parse_map` in aya-0.14.0/src/bpf.rs (29 types; aya 0.13.1 had
    /// 20). Any other type fails `EbpfLoader::load` for the WHOLE object
    /// ("Unsupported map type found N") after the kernel created the map,
    /// unless `allow_unsupported_maps` is set, which the agent does not do.
    /// Re-derive the list from that function when aya is upgraded
    /// ([`aya_is_the_version_the_list_was_read_from`]).
    const AYA_0_14_MAP_TYPES: &[aya_obj::generated::bpf_map_type] = {
        use aya_obj::generated::bpf_map_type::*;
        &[
            BPF_MAP_TYPE_ARRAY,
            BPF_MAP_TYPE_PERCPU_ARRAY,
            BPF_MAP_TYPE_PROG_ARRAY,
            BPF_MAP_TYPE_CGROUP_ARRAY,
            BPF_MAP_TYPE_CGROUP_STORAGE_DEPRECATED,
            BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE_DEPRECATED,
            BPF_MAP_TYPE_HASH,
            BPF_MAP_TYPE_LRU_HASH,
            BPF_MAP_TYPE_PERCPU_HASH,
            BPF_MAP_TYPE_LRU_PERCPU_HASH,
            BPF_MAP_TYPE_PERF_EVENT_ARRAY,
            BPF_MAP_TYPE_REUSEPORT_SOCKARRAY,
            BPF_MAP_TYPE_RINGBUF,
            BPF_MAP_TYPE_SOCKHASH,
            BPF_MAP_TYPE_SOCKMAP,
            BPF_MAP_TYPE_BLOOM_FILTER,
            BPF_MAP_TYPE_LPM_TRIE,
            BPF_MAP_TYPE_STACK,
            BPF_MAP_TYPE_STACK_TRACE,
            BPF_MAP_TYPE_QUEUE,
            BPF_MAP_TYPE_CPUMAP,
            BPF_MAP_TYPE_DEVMAP,
            BPF_MAP_TYPE_DEVMAP_HASH,
            BPF_MAP_TYPE_XSKMAP,
            BPF_MAP_TYPE_SK_STORAGE,
            BPF_MAP_TYPE_INODE_STORAGE,
            BPF_MAP_TYPE_CGRP_STORAGE,
            BPF_MAP_TYPE_ARRAY_OF_MAPS,
            BPF_MAP_TYPE_HASH_OF_MAPS,
        ]
    };

    /// The class of lab PR 219's boot failure (Debian 12: "loading eBPF
    /// object (BTF, maps, programs) / map error: Unsupported map type found
    /// 29", a hand-declared task-storage map): every map of the embedded
    /// object — `#[map]`, BTF `.maps`, global data — read by aya-obj 0.3.0,
    /// the parser aya 0.14.0 itself runs, must have a type aya 0.14 hands
    /// out. Parsing alone is not enough: aya-obj accepts any type the
    /// kernel knows.
    ///
    /// A userland-only build (CI's `test` job) embeds no object and skips;
    /// where the object is built (CI's `ebpf` job, after `cargo xtask
    /// build-ebpf`) [`REQUIRE_OBJECT_ENV`] is set and a build without it
    /// fails instead of passing as skipped.
    #[test]
    fn every_map_is_one_the_agents_aya_loads() {
        if EMBEDDED != "1" || EBPF_BYTES.is_empty() {
            assert!(
                std::env::var_os(REQUIRE_OBJECT_ENV).is_none(),
                "{REQUIRE_OBJECT_ENV} is set but this build embeds no eBPF object: \
                 run `cargo xtask build-ebpf` before the test"
            );
            eprintln!(
                "no embedded eBPF object in this build: skipped \
                 ({REQUIRE_OBJECT_ENV}=1 fails instead)"
            );
            return;
        }
        let obj = aya_obj::Object::parse(EBPF_BYTES).expect("the eBPF object parses");
        assert!(!obj.maps.is_empty(), "the object declares maps");
        let mut refused: Vec<String> = Vec::new();
        for (name, map) in &obj.maps {
            let t = map.map_type();
            match aya_obj::generated::bpf_map_type::try_from(t) {
                Ok(ty) if AYA_0_14_MAP_TYPES.contains(&ty) => {}
                Ok(ty) => refused.push(format!("{name}: {ty:?} ({t})")),
                Err(_) => refused.push(format!("{name}: unknown map type {t}")),
            }
        }
        refused.sort();
        assert!(
            refused.is_empty(),
            "maps aya 0.14 cannot load — the agent would refuse to start on every kernel: {refused:?}"
        );
    }

    /// [`AYA_0_14_MAP_TYPES`] was read from aya 0.14.0: an upgrade of the
    /// agent's aya must re-read it (a newer aya may load more types).
    #[test]
    fn aya_is_the_version_the_list_was_read_from() {
        let lock =
            std::fs::read_to_string(std::path::Path::new(env!("NN_REPO_ROOT")).join("Cargo.lock"))
                .expect("the workspace Cargo.lock");
        let aya = lock
            .split("[[package]]")
            .find(|p| p.contains("\nname = \"aya\"\n"))
            .expect("aya in Cargo.lock");
        assert!(
            aya.contains("\nversion = \"0.14.0\"\n"),
            "aya changed: re-derive AYA_0_14_MAP_TYPES from its src/bpf.rs parse_map: {aya}"
        );
    }
}
