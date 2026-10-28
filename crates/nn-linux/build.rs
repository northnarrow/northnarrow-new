//! Build script: stage the compiled eBPF object so the agent can embed
//! it via `include_bytes!` — and **refuse to embed a stale one**.
//!
//! `agent-ebpf/` is a sibling cargo project (not a workspace member,
//! see the root `Cargo.toml`). Only `cargo xtask build[-ebpf]` compiles
//! it; a plain `cargo build --workspace` does not. The old version of
//! this script copied whatever `.o` was on disk and only watched the
//! *artifact path* for changes — so an eBPF / wire-type source edit
//! that was never recompiled into the `.o` got SILENTLY embedded. With
//! the kernel↔userland struct keeping the same size (a new field carved
//! from reclaimed padding), the `bytemuck` size-check passed and the
//! staleness was invisible. That is the bug that made R011 over-fire.
//!
//! The guard, implemented here + in the shared [`ebpf_guard`] crate:
//!   * `cargo xtask build-ebpf` writes a provenance *stamp* (a hash of
//!     the eBPF source closure, and the SHA-256 of the object it just
//!     built) next to the `.o`.
//!   * This script recomputes the source hash over the current tree,
//!     hashes the object bytes it is about to embed, and **fails the
//!     build, loudly**, if the `.o` is present but its stamp is missing
//!     or either hash does not match. So a stale object, or one that is
//!     not the object xtask stamped, can no longer be embedded — the
//!     build stops instead.
//!   * If the `.o` is entirely absent (CI userland job, IDE `cargo
//!     check`), we fall back to an empty placeholder so those builds
//!     stay green; the agent then *refuses to start* at runtime (its
//!     boot preflight rejects an unembedded/placeholder object).
//!
//! The two layers — fail-loud-at-build for a stale object, refuse-at-
//! startup for an absent one — make "the eBPF object is rebuilt
//! atomically with the agent" an enforced invariant, not a comment.

use std::{env, fs, path::PathBuf};

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR set by cargo"));
    let dst = out_dir.join("northnarrow-agent-ebpf");

    let repo_root = PathBuf::from(env::var_os("NN_REPO_ROOT").expect("NN_REPO_ROOT ([env])"));

    let ebpf_artifact = ebpf_guard::ebpf_artifact_path(&repo_root);
    let stamp_path = ebpf_guard::ebpf_stamp_path(&repo_root);

    // Re-run when ANY eBPF source-closure input changes — not just the
    // artifact. Watching only the artifact (the prior behaviour) is why
    // a source edit never re-triggered this script and the staleness
    // slipped through. Watching the source set means an edit forces a
    // re-evaluation of the staleness guard on the next build.
    match ebpf_guard::source_inputs(&repo_root) {
        Ok(inputs) => {
            for p in inputs {
                println!("cargo:rerun-if-changed={}", p.display());
            }
        }
        Err(e) => println!(
            "cargo:warning=ebpf-guard: could not enumerate eBPF source inputs ({e}); \
             staleness re-detection may be incomplete"
        ),
    }
    println!("cargo:rerun-if-changed={}", ebpf_artifact.display());
    println!("cargo:rerun-if-changed={}", stamp_path.display());
    println!("cargo:rerun-if-changed=build.rs");

    if ebpf_artifact.is_file() {
        // The object exists → it MUST be provably fresh. Read it once:
        // the bytes checked against the stamp are the bytes staged for
        // `include_bytes!`, and the runtime preflight re-derives their
        // sha to catch post-build corruption / object swap.
        let bytes = fs::read(&ebpf_artifact)
            .unwrap_or_else(|e| panic!("reading eBPF artifact {}: {e}", ebpf_artifact.display()));
        let obj_sha = ebpf_guard::sha256_hex(&bytes);
        let current = ebpf_guard::ebpf_source_hash(&repo_root).unwrap_or_else(|e| {
            panic!("ebpf-guard: failed to hash the eBPF source closure: {e}");
        });
        let stamp = ebpf_guard::read_stamp(&repo_root)
            .unwrap_or_else(|e| panic!("ebpf-guard: failed to read the eBPF build stamp: {e}"));
        match ebpf_guard::verdict(stamp.as_ref(), &current, &obj_sha) {
            // Fresh: built from the current source, and these are the
            // bytes xtask stamped. Fall through to embed them.
            ebpf_guard::Verdict::Fresh => {}
            // Present but STALE: the .o was built from different source.
            ebpf_guard::Verdict::StaleSource { stamped, current } => panic!(
                "\n\
                ═══════════════════════════════════════════════════════════════════════\n\
                  STALE eBPF OBJECT — refusing to embed (agent/build.rs staleness guard)\n\
                ═══════════════════════════════════════════════════════════════════════\n\
                The compiled eBPF object at\n    {artifact}\n\
                was built from a DIFFERENT source tree than the one compiling now:\n\
                    stamped source hash : {stamped}\n    \
                    current source hash : {current}\n\n\
                `cargo build` does NOT rebuild the eBPF object — it is a separate cargo\n\
                project (nightly + bpfel target) that only `cargo xtask` compiles. eBPF\n\
                or wire-type source changed without rebuilding the .o, so a plain build\n\
                would have SILENTLY embedded the old kernel logic. (That is the exact\n\
                failure that made R011 over-fire on benign kworker→modprobe execs.)\n\n\
                Fix — rebuild the eBPF object atomically with the agent:\n\
                    cargo xtask build --release      (or: cargo xtask build-ebpf)\n\
                ═══════════════════════════════════════════════════════════════════════\n",
                artifact = ebpf_artifact.display(),
            ),
            // Same source, other bytes: not the object xtask stamped
            // (rebuilt outside xtask, or replaced after the stamp).
            ebpf_guard::Verdict::ObjectMismatch { stamped, actual } => panic!(
                "\n\
                ═══════════════════════════════════════════════════════════════════════\n\
                  eBPF OBJECT DOES NOT MATCH ITS STAMP — refusing to embed (agent/build.rs)\n\
                ═══════════════════════════════════════════════════════════════════════\n\
                The compiled eBPF object at\n    {artifact}\n\
                is not the object `cargo xtask build-ebpf` stamped:\n    \
                    stamped object sha256 : {stamped}\n    \
                    actual object sha256  : {actual}\n\n\
                It was rebuilt outside xtask (other flags or toolchain, an IDE, a plain\n\
                `cargo build` in agent-ebpf/) or replaced after the stamp was written.\n\n\
                Fix — rebuild it through xtask so it is stamped:\n\
                    cargo xtask build --release      (or: cargo xtask build-ebpf)\n\
                ═══════════════════════════════════════════════════════════════════════\n",
                artifact = ebpf_artifact.display(),
            ),
            // Present but UNSTAMPED: provenance unknown (pre-guard build,
            // a stamp of an older format, or hand-copied). Cannot prove
            // freshness → refuse.
            ebpf_guard::Verdict::Unstamped => panic!(
                "\n\
                ═══════════════════════════════════════════════════════════════════════\n\
                  UNSTAMPED eBPF OBJECT — refusing to embed (agent/build.rs guard)\n\
                ═══════════════════════════════════════════════════════════════════════\n\
                The compiled eBPF object at\n    {artifact}\n\
                has no usable provenance stamp ({stamp}), so its freshness cannot be\n\
                proven. It was produced by a pre-guard build, stamped in an older format\n\
                (a one-time rebuild after an upgrade), or copied in by hand.\n\n\
                Fix — rebuild it through xtask so it is stamped:\n\
                    cargo xtask build --release      (or: cargo xtask build-ebpf)\n\
                ═══════════════════════════════════════════════════════════════════════\n",
                artifact = ebpf_artifact.display(),
                stamp = stamp_path.display(),
            ),
        }

        fs::write(&dst, &bytes).expect("copy eBPF object into OUT_DIR");
        println!("cargo:rustc-env=NN_EBPF_EMBEDDED=1");
        println!("cargo:rustc-env=NN_EBPF_OBJECT_SHA={obj_sha}");
        println!("cargo:rustc-env=NN_EBPF_BUILD_HASH={current}");
    } else {
        // No artifact yet — keep the build green for `cargo build
        // --workspace` (CI userland job, IDE checks). The agent's boot
        // preflight refuses to start on this placeholder, so an
        // unembedded build can never run blind in production.
        fs::write(&dst, b"").expect("create empty placeholder");
        println!("cargo:rustc-env=NN_EBPF_EMBEDDED=0");
        println!("cargo:rustc-env=NN_EBPF_OBJECT_SHA=");
        println!("cargo:rustc-env=NN_EBPF_BUILD_HASH=absent");
        println!(
            "cargo:warning=eBPF artifact not found at {}. Build it with `cargo xtask build-ebpf`; \
             the agent will REFUSE TO START until then (boot preflight rejects the placeholder).",
            ebpf_artifact.display()
        );
    }
}
