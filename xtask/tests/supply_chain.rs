//! Supply-chain hygiene of the repository itself: what the CI runs, how
//! releases are verified, and what the default build targets. External
//! audit SUP-001, SUP-002, SUP-005, SUP-017 and DEP-008. Each test reads
//! committed files only; nothing runs a tool or touches the network.

use std::fs;
use std::path::{Path, PathBuf};

/// The certificate identity every attestation check must require: the
/// release workflow of this repository, run for a `v*` tag (SUP-001).
const RELEASE_IDENTITY_REGEX: &str =
    r"^https://github\.com/northnarrow/northnarrow-new/\.github/workflows/release\.yml@refs/tags/v";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives one level below the repository root")
        .to_path_buf()
}

fn rel(path: &Path) -> String {
    path.strip_prefix(repo_root())
        .unwrap_or(path)
        .display()
        .to_string()
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn workflow_files() -> Vec<PathBuf> {
    let dir = repo_root().join(".github/workflows");
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.expect("readable directory entry").path())
        .filter(|p| matches!(p.extension().and_then(|e| e.to_str()), Some("yml" | "yaml")))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no workflow under {}", dir.display());
    files
}

/// Every file under `dir` (recursively) whose name ends with one of `exts`.
fn files_under(dir: &Path, exts: &[&str], skip: &[&str]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = fs::read_dir(&d) else {
            continue;
        };
        for entry in entries {
            let path = entry.expect("readable directory entry").path();
            if skip.iter().any(|s| rel(&path).starts_with(s)) {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
            } else if exts.iter().any(|ext| path.to_string_lossy().ends_with(ext)) {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// `vX.Y.Z` with numeric parts.
fn is_full_version(s: &str) -> bool {
    let Some(v) = s.strip_prefix('v') else {
        return false;
    };
    let parts: Vec<&str> = v.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// The `uses:` value of a workflow line and what follows it, if the line is one.
fn uses_of(line: &str) -> Option<(&str, &str)> {
    let t = line.trim_start();
    let t = t.strip_prefix("- ").unwrap_or(t).trim_start();
    let rest = t.strip_prefix("uses:")?.trim();
    let value = rest.split_whitespace().next()?;
    Some((value, rest[value.len()..].trim()))
}

/// SUP-002: a tag can be moved to other code by whoever controls the
/// action's repository; a full commit SHA cannot. The version comment is
/// what a reviewer reads and what Dependabot keeps in step with the SHA.
#[test]
fn every_action_is_pinned_by_full_commit_sha() {
    let mut seen = 0;
    let mut bad = Vec::new();
    for file in workflow_files() {
        for (n, line) in read(&file).lines().enumerate() {
            let Some((value, comment)) = uses_of(line) else {
                continue;
            };
            seen += 1;
            if value.starts_with("./") {
                continue; // an action of this repository, pinned by the checkout
            }
            let ok = match value.split_once('@') {
                Some((name, sha)) if value.starts_with("docker://") => {
                    !name.is_empty() && sha.starts_with("sha256:")
                }
                Some((name, sha)) => {
                    name.contains('/')
                        && sha.len() == 40
                        && sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
                        && comment
                            .strip_prefix('#')
                            .is_some_and(|c| is_full_version(c.trim()))
                }
                None => false,
            };
            if !ok {
                bad.push(format!("{}:{}: {}", rel(&file), n + 1, line.trim()));
            }
        }
    }
    assert!(seen > 0, "no `uses:` line found");
    assert!(
        bad.is_empty(),
        "actions must be pinned as `owner/repo@<40-hex sha> # vX.Y.Z`:\n{}",
        bad.join("\n")
    );
}

/// SUP-005: `cargo install` without `--version` takes whatever crates.io
/// serves that day; `--locked` pins the tool's own dependencies.
#[test]
fn every_cargo_install_names_a_version_and_is_locked() {
    let root = repo_root();
    let mut files = workflow_files();
    files.extend(files_under(&root.join("deploy"), &[".sh"], &[]));
    let mut seen = 0;
    let mut bad = Vec::new();
    for file in files {
        for (n, line) in read(&file).lines().enumerate() {
            let Some(at) = line.find("cargo install ") else {
                continue;
            };
            let cmd = &line[at..];
            if cmd.starts_with("cargo install --list") {
                continue;
            }
            seen += 1;
            if !(cmd.contains("--version ") || cmd.contains("--version="))
                || !cmd.contains("--locked")
            {
                bad.push(format!("{}:{}: {}", rel(&file), n + 1, line.trim()));
            }
        }
    }
    assert!(seen > 0, "no `cargo install` line found");
    assert!(
        bad.is_empty(),
        "`cargo install` needs --version and --locked:\n{}",
        bad.join("\n")
    );
}

/// SUP-017: the committed default must produce binaries that start on any
/// supported x86_64 host. `native` is a local opt-in, never the default.
#[test]
fn repository_default_target_cpu_is_portable() {
    let root = repo_root();
    let config = read(&root.join(".cargo/config.toml"));
    let settings: Vec<&str> = config
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .collect();
    assert!(
        !settings.iter().any(|l| l.contains("target-cpu=native")),
        ".cargo/config.toml must not default to target-cpu=native"
    );
    assert!(
        settings
            .iter()
            .any(|l| l.starts_with("rustflags") && l.contains("target-cpu=x86-64-v2")),
        ".cargo/config.toml must default to target-cpu=x86-64-v2"
    );
    // The release keeps its explicit override and its ISA check.
    let release = read(&root.join(".github/workflows/release.yml"));
    assert!(release
        .contains(r#"CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS: "-C target-cpu=x86-64-v2""#));
    assert!(release.contains("qemu-x86_64 -cpu Nehalem"));
}

/// Joins `lines[i]` with the lines it continues onto (trailing `\`).
fn logical_command(lines: &[&str], i: usize) -> String {
    let mut cmd = String::new();
    let mut j = i;
    while j < lines.len() {
        let l = lines[j].trim_end();
        cmd.push_str(l.trim_end_matches('\\'));
        cmd.push(' ');
        if !l.ends_with('\\') {
            break;
        }
        j += 1;
    }
    cmd
}

/// SUP-001: `--repo` alone, or `--signer-workflow`, accepts the attestation
/// of a dispatch run of the release workflow on any branch. Every command
/// the repository tells an operator (or runs itself) must require the
/// release workflow at a `v*` tag.
#[test]
fn every_attestation_check_is_bound_to_a_release_tag() {
    let root = repo_root();
    let mut files = vec![root.join("README.md")];
    files.extend(files_under(&root.join("docs"), &[".md"], &["docs/audit"]));
    files.extend(files_under(&root.join("deploy"), &[".sh", ".md"], &[]));
    files.extend(workflow_files());
    const COMMAND_FLAGS: [&str; 6] = [
        "--repo",
        "--owner",
        "--bundle ",
        "--signer-",
        "--cert-identity",
        "--certificate-identity",
    ];
    let mut commands = 0;
    let mut bad = Vec::new();
    for file in files {
        let text = read(&file);
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let gh = line.contains("attestation verify");
            let cosign = line.contains("verify-blob-attestation");
            if !gh && !cosign {
                continue;
            }
            let cmd = logical_command(&lines, i);
            if !COMMAND_FLAGS.iter().any(|f| cmd.contains(f)) {
                continue; // prose naming the command
            }
            commands += 1;
            let identity =
                cmd.contains(RELEASE_IDENTITY_REGEX) || cmd.contains("$SIGNER_IDENTITY_REGEX");
            let ok = !cmd.contains("--signer-workflow")
                && !cmd.contains("--signer-repo")
                && identity
                && if cosign {
                    cmd.contains("--certificate-identity-regexp")
                } else {
                    cmd.contains("--cert-identity-regex")
                        && cmd.contains("--deny-self-hosted-runners")
                };
            if !ok {
                bad.push(format!("{}:{}: {}", rel(&file), i + 1, cmd.trim()));
            }
        }
    }
    // install.sh's verifier uses the same identity
    let install = read(&root.join("deploy/install.sh"));
    assert!(
        install.contains(&format!("SIGNER_IDENTITY_REGEX='{RELEASE_IDENTITY_REGEX}'")),
        "deploy/install.sh must define SIGNER_IDENTITY_REGEX as the release-tag identity"
    );
    assert!(
        commands >= 6,
        "expected the verify commands of README, the operator guide, release.yml, mk-tarball.sh and install.sh; found {commands}"
    );
    assert!(
        bad.is_empty(),
        "attestation checks must require the release workflow at a v* tag \
         (--cert-identity-regex '{RELEASE_IDENTITY_REGEX}' --deny-self-hosted-runners):\n{}",
        bad.join("\n")
    );
}

/// DEP-008: the .rpm is signed on a tag only, by a job that holds the key
/// and nothing else; the job that holds the OIDC token never sees the key,
/// and a tag cannot publish without the signing job.
#[test]
fn rpm_is_signed_on_tags_by_its_own_job() {
    let root = repo_root();
    let text = read(&root.join(".github/workflows/release.yml"));
    let wf: serde_yaml_ng::Value = serde_yaml_ng::from_str(&text).expect("release.yml parses");
    let jobs = wf.get("jobs").expect("release.yml has jobs");
    let job_text = |name: &str| {
        serde_yaml_ng::to_string(jobs.get(name).unwrap_or_else(|| panic!("job {name}"))).unwrap()
    };

    let rpm_sign = jobs
        .get("rpm-sign")
        .expect("release.yml has an rpm-sign job");
    let cond = rpm_sign.get("if").and_then(|v| v.as_str()).unwrap_or("");
    assert!(
        cond.contains("refs/tags/v"),
        "rpm-sign must run on v* tags only, got `{cond}`"
    );
    assert_eq!(
        rpm_sign.get("environment").and_then(|v| v.as_str()),
        Some("release-signing"),
        "the signing key lives in the tag-restricted release-signing environment"
    );
    let perms = rpm_sign
        .get("permissions")
        .expect("rpm-sign declares its permissions");
    assert_eq!(perms.get("contents").and_then(|v| v.as_str()), Some("read"));
    assert!(
        perms.get("id-token").is_none(),
        "rpm-sign must not get an OIDC token"
    );
    let rpm_sign_text = job_text("rpm-sign");
    for needle in [
        "sign-rpm.sh sign",
        "sign-rpm.sh verify",
        "RPM-GPG-KEY-northnarrow.asc",
        "SHA256SUMS",
    ] {
        assert!(
            rpm_sign_text.contains(needle),
            "rpm-sign must use `{needle}`"
        );
    }

    for (name, _) in jobs.as_mapping().expect("jobs is a mapping") {
        let name = name.as_str().expect("job names are strings");
        if name != "rpm-sign" {
            assert!(
                !job_text(name).contains("RPM_SIGNING"),
                "only rpm-sign may reference the rpm signing secrets (found in {name})"
            );
        }
    }

    let needs = job_text("sign");
    assert!(
        jobs.get("sign")
            .and_then(|j| j.get("needs"))
            .and_then(|n| n.as_sequence())
            .is_some_and(|s| s.iter().any(|v| v.as_str() == Some("rpm-sign"))),
        "sign must wait for rpm-sign:\n{needs}"
    );
    let sign_if = jobs
        .get("sign")
        .and_then(|j| j.get("if"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(
        sign_if.contains("needs.rpm-sign.result == 'success'"),
        "on a tag, sign must require a successful rpm-sign, got `{sign_if}`"
    );
    assert!(
        job_text("package").contains("sign-rpm.sh selftest"),
        "the package job exercises the signing path on every run"
    );

    let script = root.join("deploy/release/sign-rpm.sh");
    assert!(script.is_file(), "deploy/release/sign-rpm.sh is missing");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&script).unwrap().permissions().mode();
        assert!(
            mode & 0o111 != 0,
            "deploy/release/sign-rpm.sh must be executable"
        );
    }
}

/// Every workflow is valid YAML with jobs (actionlint is not part of CI).
#[test]
fn workflows_parse_as_yaml() {
    for file in workflow_files() {
        let wf: serde_yaml_ng::Value =
            serde_yaml_ng::from_str(&read(&file)).unwrap_or_else(|e| panic!("{}: {e}", rel(&file)));
        assert!(
            wf.get("jobs")
                .and_then(|j| j.as_mapping())
                .is_some_and(|m| !m.is_empty()),
            "{}: no jobs",
            rel(&file)
        );
    }
}
