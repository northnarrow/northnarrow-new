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

mod attack;
mod btf_check;
mod gate_report;

const EBPF_TARGET: &str = "bpfel-unknown-none";
const EBPF_PACKAGE: &str = "northnarrow-agent-ebpf";
const AGENT_PACKAGE: &str = "northnarrow-agent";

#[derive(Parser, Debug)]
#[command(name = "xtask", about = "NorthNarrow workspace task runner", version)]
struct Cli {
    /// Pass `--locked` to every nested cargo build (external audit
    /// SUP-016): the build fails instead of rewriting `Cargo.lock` or
    /// `agent-ebpf/Cargo.lock` when a manifest no longer matches it. xtask
    /// clears the parent cargo's environment, so the parent's own
    /// `--locked` cannot reach those builds: CI and the release run
    /// `cargo --locked xtask … --locked`.
    #[arg(long, global = true)]
    locked: bool,
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
    /// Build, then run the agent with sudo (needs CAP_BPF/root); only
    /// `RUST_LOG` is passed through.
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
    // `ade-demo` and `rag-kb` (the LLM advisor's demo and its knowledge
    // base) were removed with the advisor in Wave 4, lab PR 214.
    /// Lab PR 227: judge one guest's privileged-suite run from the output
    /// of `deploy/lab/nn-lab.sh test-ignored` — suites, passed, failed,
    /// ignored, the expected failures of deploy/lab/expected-failures.tsv
    /// shown with their outcome — and write gate-summary.json (and the
    /// Markdown of the CI job summary). Exits 1 when the gate fails.
    GateSummary {
        /// The saved output of `nn-lab.sh test-ignored` (stdout and stderr).
        /// Missing: the gate did not run, and the summary says so.
        #[arg(long)]
        log: PathBuf,
        /// The guest (NN_LAB_DISTRO); selects the expected failures.
        #[arg(long)]
        distro: String,
        /// The guest's kernel (`uname -r`).
        #[arg(long, default_value = "")]
        kernel: String,
        /// The exit status of `nn-lab.sh test-ignored`.
        #[arg(long)]
        rc: Option<i32>,
        /// The workflow's steps before the summary, `NAME=OUTCOME`
        /// (`steps.<id>.outcome`), repeated; any outcome but `success`
        /// fails the gate.
        #[arg(long = "step", value_name = "NAME=OUTCOME")]
        steps: Vec<String>,
        /// The tested commit.
        #[arg(long, default_value = "")]
        commit: String,
        /// The workflow run.
        #[arg(long, default_value = "")]
        run_url: String,
        #[arg(long, default_value = "deploy/lab/expected-failures.tsv")]
        expected: PathBuf,
        /// Where the machine-readable summary goes.
        #[arg(long, default_value = gate_report::SUMMARY_FILE)]
        json: PathBuf,
        /// Where the job summary's Markdown goes.
        #[arg(long)]
        markdown: Option<PathBuf>,
    },
    /// Lab PR 227: one Markdown table (a row per guest kernel) from
    /// gate-summary.json files or the directories holding them, e.g. the
    /// artefacts of a lab-vm run (`gh run download <run id> -D DIR`), for
    /// the maintainer to commit under docs/validation/results/.
    GateReport {
        /// gate-summary.json files, or directories searched for them.
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Write the report here instead of stdout.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Lab PR 221 (capability C16): render docs/detection/ATTACK_COVERAGE.md,
    /// RULE_CATALOGUE.md and attack-navigator-layer.json from the rules'
    /// ATT&CK mapping and the catalogue table (agent library, through the
    /// `attack_coverage` example). With `--pin-ids`, first rebuild the
    /// pinned ATT&CK id list (docs/detection/attack-enterprise-20.0.tsv)
    /// and its licence from a local copy of MITRE's STIX bundle, checked
    /// against its pinned SHA-256.
    AttackCoverage {
        /// Write nothing; fail when a committed document differs from the
        /// rendered one.
        #[arg(long, conflicts_with = "pin_ids")]
        check: bool,
        /// Rebuild the pinned id list first, keeping the ids it lists and
        /// adding these (comma-separated, e.g. `T1053.003,DC0039`).
        #[arg(long, num_args = 0.., value_delimiter = ',', requires = "mirror")]
        pin_ids: Option<Vec<String>>,
        /// With `--pin-ids`: the directory holding the pinned
        /// `enterprise-attack-20.0.json` and `LICENSE.txt` of
        /// mitre-attack/attack-stix-data (the example prints their URLs).
        #[arg(long, requires = "pin_ids")]
        mirror: Option<PathBuf>,
    },
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
    let locked = cli.locked;
    match cli.cmd {
        Cmd::BuildEbpf { release } => {
            ensure_bpf_linker()?;
            build_ebpf(release, locked)?;
        }
        Cmd::Build { release, features } => {
            ensure_bpf_linker()?;
            build_ebpf(true, locked)?; // eBPF always release
            build_userland(release, &features, locked)?;
        }
        Cmd::Run {
            release,
            no_sudo,
            features,
            args,
        } => {
            ensure_bpf_linker()?;
            build_ebpf(true, locked)?;
            build_userland(release, &features, locked)?;
            run_agent(release, no_sudo, &args)?;
        }
        Cmd::InspectEbpf => inspect_ebpf()?,
        Cmd::GateSummary {
            log,
            distro,
            kernel,
            rc,
            steps,
            commit,
            run_url,
            expected,
            json,
            markdown,
        } => gate_summary(GateSummaryArgs {
            log,
            distro,
            kernel,
            rc,
            steps,
            commit,
            run_url,
            expected,
            json,
            markdown,
        })?,
        Cmd::GateReport { paths, out } => {
            let mut summaries = Vec::new();
            for p in gate_report::find_summaries(&paths)? {
                summaries.push(gate_report::read_summary(&p)?);
            }
            let md = gate_report::report_markdown(&summaries);
            match out {
                Some(path) => write_creating_dirs(&path, &md)?,
                None => print!("{md}"),
            }
        }
        Cmd::AttackCoverage {
            check,
            pin_ids,
            mirror,
        } => {
            let root = repo_root()?;
            let req = attack::Request {
                check,
                pin_ids: pin_ids.as_deref(),
                mirror: mirror.as_deref(),
            };
            attack::run(&root, &req, locked)?;
        }
    }
    Ok(())
}

fn write_creating_dirs(path: &Path, text: &str) -> Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    std::fs::write(path, text).with_context(|| format!("writing {}", path.display()))
}

struct GateSummaryArgs {
    log: PathBuf,
    distro: String,
    kernel: String,
    rc: Option<i32>,
    steps: Vec<String>,
    commit: String,
    run_url: String,
    expected: PathBuf,
    json: PathBuf,
    markdown: Option<PathBuf>,
}

/// `cargo xtask gate-summary`: the files first, the verdict last, so a
/// failed gate still leaves its summary for the job summary and the
/// artefacts.
fn gate_summary(a: GateSummaryArgs) -> Result<()> {
    let expected_text = std::fs::read_to_string(&a.expected)
        .with_context(|| format!("reading {}", a.expected.display()))?;
    let expected = gate_report::parse_expected(&expected_text)
        .with_context(|| format!("in {}", a.expected.display()))?;
    let log = match std::fs::read(&a.log) {
        Ok(bytes) => Some(String::from_utf8_lossy(&bytes).into_owned()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).with_context(|| format!("reading {}", a.log.display())),
    };
    let steps = a
        .steps
        .iter()
        .map(|s| gate_report::parse_step(s))
        .collect::<Result<Vec<_>>>()?;
    let inputs = gate_report::Inputs {
        distro: a.distro,
        kernel: a.kernel,
        commit: a.commit,
        run_url: a.run_url,
        exit_status: a.rc,
        steps,
    };
    let summary = gate_report::evaluate(&inputs, log.as_deref(), &expected);
    let json = serde_json::to_string_pretty(&summary)? + "\n";
    write_creating_dirs(&a.json, &json)?;
    let md = gate_report::job_markdown(&summary);
    if let Some(path) = &a.markdown {
        write_creating_dirs(path, &md)?;
    }
    eprint!("{md}");
    if !summary.passed() {
        bail!(
            "the privileged-suite gate failed on {}: {}",
            summary.distro,
            summary.reasons.join("; ")
        );
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
             cargo install bpf-linker --version 0.10.3 --locked\n\
             (0.10.x uses rustc's bundled LLVM: no system LLVM packages needed)"
        );
    }
    Ok(())
}

fn build_ebpf(release: bool, locked: bool) -> Result<()> {
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
    lock_if(&mut cmd, locked);
    // Strip the parent cargo's environment so agent-ebpf's nightly
    // toolchain + bpfel target + build-std settings are picked up
    // from its own rust-toolchain.toml / .cargo/config.toml without
    // interference (notably CARGO_TARGET_DIR and CARGO_*).
    scrub_cargo_env(&mut cmd);
    // The eBPF target's flags (`-C debuginfo=2`, `--btf`, `panic=abort`)
    // live in agent-ebpf/.cargo/config.toml. A RUSTFLAGS from the
    // environment REPLACES them (cargo does not merge the two), so CI's
    // workflow-wide `RUSTFLAGS: -D warnings` built an object without its
    // .BTF section — which the LSM programs need and which the check below
    // now refuses (external audit EBPF-022, lab PR 187).
    for k in ebpf_build_dropped_env() {
        cmd.env_remove(k);
    }
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
    // External audit EBPF-022: an object without `.BTF` loads no LSM
    // program; refuse it here rather than at the agent's start on a host.
    let built = std::fs::read(&bpf_obj)
        .with_context(|| format!("reading {} for the BTF check", bpf_obj.display()))?;
    btf_check::require_btf(&built).with_context(|| format!("refusing {}", bpf_obj.display()))?;
    println!("xtask: eBPF artifact carries .BTF");

    // Stamp the RELEASE artifact (the one `agent/build.rs` embeds) with
    // the source-closure hash. This is the writer half of the staleness
    // guard: `agent/build.rs` reads this stamp and refuses to embed a
    // `.o` whose stamp does not match the current source — so a plain
    // `cargo build` can no longer silently bake in a stale object. It
    // is what makes "the eBPF object is rebuilt atomically with the
    // agent" an enforced invariant rather than a hopeful comment.
    //
    // Only release is stamped because release is the only profile the
    // agent ever embeds; a `--release=false` eBPF build is a manual
    // inspection aid and intentionally leaves no stamp (so a userland
    // build against it trips the guard).
    //
    // The stamp also records the SHA-256 of the object just built
    // (external audit EBPF-014): `agent/build.rs` refuses a `.o` whose
    // bytes differ, i.e. one rebuilt outside xtask or replaced later.
    if release {
        let source_hash = ebpf_guard::ebpf_source_hash(&root)
            .with_context(|| "hashing the eBPF source closure for the build stamp")?;
        let artifact = ebpf_guard::ebpf_artifact_path(&root);
        let object = std::fs::read(&artifact)
            .with_context(|| format!("reading {} for the build stamp", artifact.display()))?;
        let object_sha = ebpf_guard::sha256_hex(&object);
        ebpf_guard::write_stamp(&root, &source_hash, &object_sha)
            .with_context(|| "writing the eBPF build stamp")?;
        println!(
            "xtask: build stamp {} = source {}, object {}",
            ebpf_guard::ebpf_stamp_path(&root).display(),
            source_hash,
            object_sha
        );
    }
    Ok(())
}

fn build_userland(release: bool, features: &[String], locked: bool) -> Result<()> {
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
    lock_if(&mut cmd, locked);
    scrub_cargo_env(&mut cmd);
    let status = cmd
        .status()
        .with_context(|| "failed to spawn cargo for userland build")?;
    if !status.success() {
        bail!("userland build failed (exit {status})");
    }
    Ok(())
}

/// Adds `--locked` to a nested cargo invocation when xtask was asked for it.
fn lock_if(cmd: &mut Command, locked: bool) {
    if locked {
        cmd.arg("--locked");
    }
}

/// Remove the `CARGO_*` and `RUSTC*` env vars cargo injects when it
/// spawns us, so a nested `cargo` invocation doesn't accidentally pick
/// up the parent's target dir, target-triple, or toolchain choice.
fn scrub_cargo_env(cmd: &mut Command) {
    let to_drop: Vec<String> = std::env::vars()
        .map(|(k, _)| k)
        .filter(|k| scrubbed(k))
        .collect();
    for k in to_drop {
        cmd.env_remove(k);
    }
}

/// The environment flags the nested eBPF build drops on top of
/// [`scrub_cargo_env`]: they would replace the target's rustflags of
/// agent-ebpf/.cargo/config.toml (lab PR 187).
fn ebpf_build_dropped_env() -> [&'static str; 2] {
    ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"]
}

/// Whether [`scrub_cargo_env`] drops `name`.
///
/// Review 65: per-target configuration (`CARGO_TARGET_<TRIPLE>_RUSTFLAGS`,
/// `_LINKER`, `_RUNNER`) is kept. It applies to one triple only and a
/// caller sets it on purpose: the release workflow builds for x86-64-v2
/// with it instead of the runner's CPU (review 64). Scrubbing it left
/// `.cargo/config.toml`'s `target-cpu=native` in force, so a release built
/// on a runner with AVX-512 died with SIGILL on CPUs without it.
fn scrubbed(name: &str) -> bool {
    let cargo_or_rustc = name.starts_with("CARGO_")
        || name == "CARGO"
        || name.starts_with("RUSTC")
        || name == "RUSTUP_TOOLCHAIN";
    let per_target = name.starts_with("CARGO_TARGET_")
        && name != "CARGO_TARGET_DIR"
        && name != "CARGO_TARGET_TMPDIR";
    cargo_or_rustc && !per_target
}

fn run_agent(release: bool, no_sudo: bool, extra: &[String]) -> Result<()> {
    let root = repo_root()?;
    let profile_dir = if release { "release" } else { "debug" };
    let agent_bin = root.join("target").join(profile_dir).join(AGENT_PACKAGE);
    if !agent_bin.is_file() {
        bail!("agent binary missing: {}", agent_bin.display());
    }

    let mut cmd = agent_command(&agent_bin, no_sudo, extra);
    println!("xtask: launching {:?}", cmd);
    let status = cmd.status().with_context(|| "failed to spawn agent")?;
    if !status.success() {
        bail!("agent exited with {status}");
    }
    Ok(())
}

/// The agent's command line for `xtask run`. External audit WDG-018
/// (NN-AUD-367): under `sudo` it was `sudo -E`, which hands the
/// developer's shell environment to the root agent (`PATH`, `HOME`, and
/// the `NN_*` variables the agent reads, escape hatches such as
/// `NN_AUDIT_ALLOW_UNWRITABLE` among them); only `RUST_LOG` is preserved
/// now, so the log level can still be overridden. The path is passed as
/// an `OsStr` (a non-UTF-8 checkout panicked in `to_str().unwrap()`) after
/// `--`, so sudo never reads it as an option.
fn agent_command(agent_bin: &Path, no_sudo: bool, extra: &[String]) -> Command {
    let mut c = if no_sudo {
        Command::new(agent_bin)
    } else {
        let mut c = Command::new("sudo");
        c.arg("--preserve-env=RUST_LOG").arg("--").arg(agent_bin);
        c
    };
    c.args(extra);
    c
}

#[cfg(test)]
mod tests {
    use super::{agent_command, lock_if, scrubbed, Cli, Cmd};
    use clap::Parser;
    use std::ffi::OsStr;
    use std::path::Path;
    use std::process::Command;

    #[test]
    fn run_agent_preserves_only_rust_log() {
        let bin = Path::new("/repo/target/release/northnarrow-agent");
        let extra = ["--config".to_string(), "/etc/northnarrow/agent.toml".into()];
        let cmd = agent_command(bin, false, &extra);
        assert_eq!(cmd.get_program(), "sudo");
        let args: Vec<&OsStr> = cmd.get_args().collect();
        assert_eq!(
            args,
            [
                "--preserve-env=RUST_LOG",
                "--",
                "/repo/target/release/northnarrow-agent",
                "--config",
                "/etc/northnarrow/agent.toml",
            ]
        );
        assert!(
            !args.iter().any(|a| *a == "-E" || *a == "--preserve-env"),
            "{args:?}"
        );

        let cmd = agent_command(bin, true, &extra);
        assert_eq!(cmd.get_program(), bin);
        assert_eq!(cmd.get_args().count(), 2);
    }

    #[test]
    fn run_agent_takes_a_non_utf8_path() {
        use std::os::unix::ffi::OsStrExt;
        let bin = Path::new(OsStr::from_bytes(b"/home/alice/nn-\xff/target/debug/agent"));
        let cmd = agent_command(bin, false, &[]);
        assert_eq!(cmd.get_args().nth(2), Some(bin.as_os_str()));
    }

    #[test]
    fn locked_reaches_the_nested_builds() {
        // external audit SUP-016: before or after the subcommand
        for argv in [
            &["xtask", "--locked", "build", "--release"][..],
            &["xtask", "build", "--release", "--locked"][..],
            &["xtask", "build-ebpf", "--locked"][..],
        ] {
            let cli = Cli::try_parse_from(argv).unwrap();
            assert!(cli.locked, "{argv:?}");
        }
        let cli = Cli::try_parse_from(["xtask", "build", "--release"]).unwrap();
        assert!(!cli.locked && matches!(cli.cmd, Cmd::Build { release: true, .. }));

        let mut cmd = Command::new("cargo");
        cmd.arg("build");
        lock_if(&mut cmd, true);
        assert_eq!(
            cmd.get_args().collect::<Vec<_>>(),
            ["build", "--locked"],
            "the nested build gets --locked"
        );
        let mut cmd = Command::new("cargo");
        cmd.arg("build");
        lock_if(&mut cmd, false);
        assert_eq!(cmd.get_args().count(), 1);
    }

    #[test]
    fn per_target_configuration_reaches_the_nested_build() {
        // review 65: the release workflow's x86-64-v2 override
        assert!(!scrubbed("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS"));
        assert!(!scrubbed("CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER"));
        // what the parent cargo or rustup chose stays out
        for name in [
            "CARGO_TARGET_DIR",
            "CARGO_BUILD_TARGET",
            "CARGO_MANIFEST_DIR",
            "CARGO_PKG_NAME",
            "CARGO",
            "RUSTC",
            "RUSTC_WRAPPER",
            "RUSTUP_TOOLCHAIN",
        ] {
            assert!(scrubbed(name), "{name}");
        }
        assert!(!scrubbed("RUSTFLAGS") && !scrubbed("PATH"));
    }

    /// Lab PR 187: the nested eBPF build drops the environment rustflags,
    /// which would replace the target's `-C debuginfo=2` and `--btf`.
    #[test]
    fn the_ebpf_build_drops_environment_rustflags() {
        assert!(super::ebpf_build_dropped_env().contains(&"RUSTFLAGS"));
        assert!(super::ebpf_build_dropped_env().contains(&"CARGO_ENCODED_RUSTFLAGS"));
    }
}
