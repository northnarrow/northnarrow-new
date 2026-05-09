//! Workspace task runner.
//!
//! The eBPF crate (`agent-ebpf/`) lives outside the userland workspace
//! because it requires nightly + `-Zbuild-std=core` and targets
//! `bpfel-unknown-none`. This binary wraps the cargo invocations the
//! humans (and CI) need: build-ebpf, build (full), run (with sudo).

use std::{
    error::Error,
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};

const EBPF_TARGET: &str = "bpfel-unknown-none";
const EBPF_PACKAGE: &str = "northnarrow-agent-ebpf";
const AGENT_PACKAGE: &str = "northnarrow-agent";

#[derive(Parser, Debug)]
#[command(name = "xtask", about = "NorthNarrow workspace task runner", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Build only the eBPF program (separate toolchain + target).
    BuildEbpf {
        /// Build in release mode (default for eBPF: required for the
        /// verifier to be happy and for sane code size).
        #[arg(long, default_value_t = true)]
        release: bool,
    },
    /// Build the full project: eBPF program + userland workspace.
    Build {
        /// Build the userland in release mode.
        #[arg(long)]
        release: bool,
        /// Comma-separated cargo features for the userland build,
        /// e.g. `--features demo-tappa5`. Forwarded as
        /// `--features <list>` to `cargo build --workspace`.
        #[arg(long, value_delimiter = ',')]
        features: Vec<String>,
    },
    /// Build, then run the agent with sudo (needs CAP_BPF/root).
    Run {
        /// Build everything in release mode.
        #[arg(long)]
        release: bool,
        /// Skip `sudo` wrapper (caller already has the caps).
        #[arg(long)]
        no_sudo: bool,
        /// Comma-separated cargo features for the userland build.
        #[arg(long, value_delimiter = ',')]
        features: Vec<String>,
        /// Extra args forwarded to the agent.
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// Parse the eBPF ELF object via aya-obj and dump diagnostics.
    InspectEbpf,
    /// Run a hermetic ADE demo: 10 synthetic events through the
    /// engine, dump verdicts + p50/p95/p99 latency. Does not need
    /// root, eBPF, or a real GGUF — uses MockBackend.
    AdeDemo,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("xtask: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.cmd {
        Cmd::BuildEbpf { release } => {
            ensure_bpf_linker()?;
            build_ebpf(release)?;
        }
        Cmd::Build { release, features } => {
            ensure_bpf_linker()?;
            build_ebpf(true)?; // eBPF always release
            build_userland(release, &features)?;
        }
        Cmd::Run {
            release,
            no_sudo,
            features,
            args,
        } => {
            ensure_bpf_linker()?;
            build_ebpf(true)?;
            build_userland(release, &features)?;
            run_agent(release, no_sudo, &args)?;
        }
        Cmd::InspectEbpf => inspect_ebpf()?,
        Cmd::AdeDemo => ade_demo()?,
    }
    Ok(())
}

/// Hermetic demo: spins up an AdeEngine with the deterministic
/// MockBackend, runs ten synthetic events, prints verdicts and
/// stats. No GGUF, no eBPF, no root.
fn ade_demo() -> Result<()> {
    let root = repo_root()?;
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root).args([
        "run",
        "--quiet",
        "--release",
        "--example",
        "ade_demo",
        "--package",
        "northnarrow-agent",
    ]);
    scrub_cargo_env(&mut cmd);
    let status = cmd.status().with_context(|| "failed to spawn ade-demo")?;
    if !status.success() {
        bail!("ade-demo exited with {status}");
    }
    Ok(())
}

fn inspect_ebpf() -> Result<()> {
    let root = repo_root()?;
    let path = root
        .join("agent-ebpf")
        .join("target")
        .join(EBPF_TARGET)
        .join("release")
        .join(EBPF_PACKAGE);
    if !path.is_file() {
        bail!("eBPF artifact missing: {}", path.display());
    }
    let bytes = std::fs::read(&path)?;
    println!("read {} bytes from {}", bytes.len(), path.display());
    match aya_obj::Object::parse(&bytes) {
        Ok(obj) => {
            println!("programs: {}", obj.programs.len());
            for (name, prog) in &obj.programs {
                println!("  program {} (section {:?})", name, prog.section);
            }
            println!("maps: {}", obj.maps.len());
            for (name, map) in &obj.maps {
                println!("  map {} (section_index {})", name, map.section_index());
            }
        }
        Err(e) => {
            println!("PARSE ERROR: {e}");
            let mut src: Option<&dyn Error> = e.source();
            while let Some(s) = src {
                println!("  caused by: {s}");
                src = s.source();
            }
        }
    }
    Ok(())
}

/// Repository root (the workspace root, which contains this xtask crate).
fn repo_root() -> Result<PathBuf> {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let p = Path::new(manifest)
        .parent()
        .ok_or_else(|| anyhow!("xtask must live one level below the repo root"))?;
    Ok(p.to_path_buf())
}

/// Verify `bpf-linker` is on PATH; suggest an install command if not.
fn ensure_bpf_linker() -> Result<()> {
    let ok = Command::new("bpf-linker")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        bail!(
            "bpf-linker not found on PATH. Install it with:\n    \
             cargo install bpf-linker --locked\n\
             (Requires LLVM headers; on Ubuntu: apt install llvm-dev libpolly-18-dev)"
        );
    }
    Ok(())
}

fn build_ebpf(release: bool) -> Result<()> {
    let root = repo_root()?;
    let ebpf_dir = root.join("agent-ebpf");
    if !ebpf_dir.is_dir() {
        bail!("agent-ebpf/ not found at {}", ebpf_dir.display());
    }

    println!(
        "xtask: building eBPF ({}) for target {}",
        if release { "release" } else { "dev" },
        EBPF_TARGET
    );
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&ebpf_dir).arg("build");
    if release {
        cmd.arg("--release");
    }
    // Strip the parent cargo's environment so agent-ebpf's nightly
    // toolchain + bpfel target + build-std settings are picked up
    // from its own rust-toolchain.toml / .cargo/config.toml without
    // interference (notably CARGO_TARGET_DIR and CARGO_*).
    scrub_cargo_env(&mut cmd);
    let status = cmd
        .status()
        .with_context(|| "failed to spawn cargo for eBPF build")?;
    if !status.success() {
        bail!("eBPF build failed (exit {status})");
    }

    let profile_dir = if release { "release" } else { "debug" };
    let bpf_obj = ebpf_dir
        .join("target")
        .join(EBPF_TARGET)
        .join(profile_dir)
        .join(EBPF_PACKAGE);
    if !bpf_obj.is_file() {
        bail!(
            "expected eBPF artifact missing: {}\n(known build outputs are produced under \
             agent-ebpf/target/{}/{}/)",
            bpf_obj.display(),
            EBPF_TARGET,
            profile_dir
        );
    }
    println!("xtask: eBPF artifact at {}", bpf_obj.display());
    Ok(())
}

fn build_userland(release: bool, features: &[String]) -> Result<()> {
    let root = repo_root()?;
    println!(
        "xtask: building userland workspace ({}{})",
        if release { "release" } else { "dev" },
        if features.is_empty() {
            String::new()
        } else {
            format!(", features={}", features.join(","))
        }
    );
    let mut cmd = Command::new("cargo");
    cmd.current_dir(&root).args(["build", "--workspace"]);
    if release {
        cmd.arg("--release");
    }
    if !features.is_empty() {
        cmd.arg("--features").arg(features.join(","));
    }
    scrub_cargo_env(&mut cmd);
    let status = cmd
        .status()
        .with_context(|| "failed to spawn cargo for userland build")?;
    if !status.success() {
        bail!("userland build failed (exit {status})");
    }
    Ok(())
}

/// Remove the `CARGO_*` and `RUSTC*` env vars cargo injects when it
/// spawns us, so a nested `cargo` invocation doesn't accidentally pick
/// up the parent's target dir, target-triple, or toolchain choice.
fn scrub_cargo_env(cmd: &mut Command) {
    let to_drop: Vec<String> = std::env::vars()
        .map(|(k, _)| k)
        .filter(|k| {
            k.starts_with("CARGO_")
                || k == "CARGO"
                || k.starts_with("RUSTC")
                || k == "RUSTUP_TOOLCHAIN"
        })
        .collect();
    for k in to_drop {
        cmd.env_remove(k);
    }
}

fn run_agent(release: bool, no_sudo: bool, extra: &[String]) -> Result<()> {
    let root = repo_root()?;
    let profile_dir = if release { "release" } else { "debug" };
    let agent_bin = root.join("target").join(profile_dir).join(AGENT_PACKAGE);
    if !agent_bin.is_file() {
        bail!("agent binary missing: {}", agent_bin.display());
    }

    let mut cmd = if no_sudo {
        let mut c = Command::new(&agent_bin);
        c.args(extra);
        c
    } else {
        let mut c = Command::new("sudo");
        // Preserve RUST_LOG so the user can override the level.
        c.args(["-E", agent_bin.to_str().unwrap()]).args(extra);
        c
    };
    println!("xtask: launching {:?}", cmd);
    let status = cmd.status().with_context(|| "failed to spawn agent")?;
    if !status.success() {
        bail!("agent exited with {status}");
    }
    Ok(())
}
