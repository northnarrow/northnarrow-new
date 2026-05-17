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

    // Tappa 6.9 (XAI / Art. 13): stamp the build's git commit into
    // `BUILD_SHA` so it can feed the deployment `environment_hash`.
    // `unknown` keeps non-git builds (release tarballs, shallow CI
    // checkouts) compiling — the hash still binds binary/model/rules/
    // host, only the commit field degrades.
    let build_sha = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=BUILD_SHA={build_sha}");
    // `.git/HEAD` covers branch switches / detached HEAD; the refs dir
    // covers a commit on the current branch (HEAD then still points at
    // the same ref file) so BUILD_SHA re-evaluates on every commit (F4).
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads/");

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
