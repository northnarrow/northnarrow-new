//! Build script: stage the compiled eBPF object so the agent can embed
//! it via `include_bytes!`.
//!
//! `agent-ebpf/` is a sibling cargo project (not a workspace member,
//! see the root `Cargo.toml`). xtask is responsible for compiling it.
//! This script just copies the artifact into `OUT_DIR` if present, or
//! falls back to an empty placeholder so a plain
//! `cargo build --workspace` keeps working in CI; the agent then
//! refuses to start at runtime with a clear error.

use std::{env, fs, path::PathBuf};

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR set by cargo"));
    let dst = out_dir.join("northnarrow-agent-ebpf");

    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let repo_root = manifest
        .parent()
        .expect("agent crate must live one level under the repo root");
    let ebpf_artifact = repo_root
        .join("agent-ebpf")
        .join("target")
        .join("bpfel-unknown-none")
        .join("release")
        .join("northnarrow-agent-ebpf");

    println!("cargo:rerun-if-changed={}", ebpf_artifact.display());
    println!("cargo:rerun-if-changed=build.rs");

    if ebpf_artifact.is_file() {
        fs::copy(&ebpf_artifact, &dst).expect("copy eBPF object into OUT_DIR");
    } else {
        // No artifact yet — keep the build green for `cargo build
        // --workspace` (CI userland job, IDE checks). The agent will
        // fail loudly at startup if asked to load an empty program.
        fs::write(&dst, b"").expect("create empty placeholder");
        println!(
            "cargo:warning=eBPF artifact not found at {}. Build it with `cargo xtask build-ebpf`; \
             the agent will refuse to start until then.",
            ebpf_artifact.display()
        );
    }
}
