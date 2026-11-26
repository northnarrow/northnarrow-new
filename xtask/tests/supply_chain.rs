//! Supply-chain hygiene of the repository itself: what the CI runs, how
//! releases are verified, what the default build targets, and which RustSEC
//! advisories are accepted. External audit SUP-001, SUP-002, SUP-004,
//! SUP-005, SUP-006, SUP-007 to SUP-018, SUP-021 to SUP-024, DEP-008 and
//! PROC-015; and the CodeQL code scanning (lot codeql). The tests read
//! committed files; nine run a local tool and none touches the network:
//! `codeql_scans_every_language_of_the_tree` lists the tracked files
//! (`git ls-files`) and the members (`cargo metadata --offline`),
//! `prune_script_fails_closed` runs the CI prune
//! script under bash with a stub `cargo`, `advisory_exceptions_expire_in_ci`
//! runs the CI expiry check under bash with a fixed date,
//! `rust_version_covers_every_locked_dependency` runs `cargo metadata
//! --locked --offline` (the crates a workspace build downloads are enough),
//! `btf_matrix_script_passes_its_offline_tests` runs
//! `deploy/btf-matrix/run-test.sh` (bash, tar, xz, sha256sum; stub curl, gh
//! and agent), `release_tag_check_accepts_only_listed_signers` runs the
//! tag check's selftest (git and ssh-keygen, throwaway keys),
//! `allowed_signers_header_names_the_listed_keys_fingerprints` runs
//! `ssh-keygen -l` on the listed public keys,
//! `the_release_scripts_refuse_a_lab_build` runs the tarball's and the
//! packages' scripts under bash with stub binaries, and
//! `glibc_baseline_check_refuses_a_binary_that_needs_above_2_34` runs the glibc
//! check's selftest (cc and the toolchain's rust-lld).

use std::fs;
use std::path::{Path, PathBuf};

mod support;

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

/// The actions pinned at more than one `<sha> # <version>` across the
/// workflows `(file, text)`, one line each, with where each pin is.
fn pin_drift(texts: &[(String, String)]) -> Vec<String> {
    let mut pins: std::collections::BTreeMap<
        &str,
        std::collections::BTreeMap<String, Vec<String>>,
    > = std::collections::BTreeMap::new();
    for (file, text) in texts {
        for (n, line) in text.lines().enumerate() {
            let Some((value, comment)) = uses_of(line) else {
                continue;
            };
            if value.starts_with("./") || value.starts_with("docker://") {
                continue;
            }
            let Some((name, sha)) = value.split_once('@') else {
                continue;
            };
            pins.entry(name)
                .or_default()
                .entry(format!("{sha} {comment}"))
                .or_default()
                .push(format!("{file}:{}", n + 1));
        }
    }
    pins.iter()
        .filter(|(_, at)| at.len() > 1)
        .map(|(name, at)| format!("{name}: {at:?}"))
        .collect()
}

/// Lot M2: an action is pinned at one commit, with one version comment, in
/// every workflow, so that no workflow stays on an older release when
/// another moves. Dependabot moves every file's pin of an action in one
/// pull request; a change by hand moves them all too.
#[test]
fn every_action_is_pinned_alike_in_every_workflow() {
    let texts: Vec<(String, String)> = workflow_files().iter().map(|f| (rel(f), read(f))).collect();
    let drift = pin_drift(&texts);
    assert!(
        drift.is_empty(),
        "an action pinned at two commits or versions:\n{}",
        drift.join("\n")
    );

    // planted: scorecard.yml's upload-sarif one release behind codeql.yml's,
    // and the same commit under another version comment
    let sarif = "github/codeql-action/upload-sarif@";
    let (file, text) = texts
        .iter()
        .find(|(f, _)| f == SCORECARD_YML)
        .expect("scorecard.yml");
    let line = text
        .lines()
        .find(|l| uses_of(l).is_some_and(|(v, _)| v.starts_with(sarif)))
        .expect("scorecard.yml uploads its SARIF");
    let (value, comment) = uses_of(line).expect("a uses line");
    let older = line.replace(&value[sarif.len()..], &"0".repeat(40));
    let renamed = line.replace(comment, "# v0.0.1");
    assert!(older != line && renamed != line, "{line}");
    for planted in [older, renamed] {
        let mut copy = texts.clone();
        copy.push((format!("{file} (planted)"), planted));
        let drift = pin_drift(&copy);
        assert!(
            drift.len() == 1 && drift[0].starts_with("github/codeql-action/upload-sarif: "),
            "{drift:?}"
        );
    }
}

/// SUP-005, one install: its own words name `--version` and `--locked`.
fn install_is_pinned_and_locked(args: &[String]) -> bool {
    let version = args.iter().enumerate().any(|(n, a)| {
        (a == "--version" && args.get(n + 1).is_some_and(|v| !v.starts_with('-')))
            || a.strip_prefix("--version=").is_some_and(|v| !v.is_empty())
    });
    version && args.iter().any(|a| a == "--locked")
}

/// The review of #618's mini-hunt: SUP-005 read a line from its first
/// `cargo install` to its end, so a second install's flags pinned the first.
#[test]
fn every_cargo_install_on_a_line_is_judged_by_its_own_flags() {
    let judge = |line: &str| -> Vec<bool> {
        shell_lines(line)
            .iter()
            .flat_map(|l| cargo_installs(l))
            .map(|a| install_is_pinned_and_locked(&a))
            .collect()
    };
    assert_eq!(judge("cargo install foo --version 1.2.3 --locked"), [true]);
    assert_eq!(judge("cargo install --locked --version=1.2.3 foo"), [true]);
    assert_eq!(
        judge("cargo install foo && cargo install bar --version 1.2.3 --locked"),
        [false, true]
    );
    assert_eq!(
        judge("cargo install foo --version 1.2.3; cargo install bar --locked"),
        [false, false]
    );
    assert_eq!(
        judge("cargo install --locked \\\n  foo --version 1.2.3\n"),
        [true]
    );
    assert_eq!(judge("cargo install --version --locked foo"), [false]);
    assert_eq!(judge("cargo +nightly install foo --locked"), [false]);
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
        // and each install by its own words (the review of #618's
        // mini-hunt): a second install on the line lent the first its
        // flags, and a continued line was read in halves
        for line in shell_lines(&read(&file)) {
            for args in cargo_installs(&line) {
                if args.first().is_some_and(|a| a == "--list") {
                    continue;
                }
                if !install_is_pinned_and_locked(&args) {
                    bad.push(format!("{}: {}", rel(&file), line.trim()));
                }
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
    // Lab PR 239 (Wave 4 restructure R01): the x86_64 Linux target's, not
    // every target's — the portable crates are built for aarch64, Windows
    // and macOS too — and a string, which CARGO_TARGET_…_RUSTFLAGS replaces
    // (a list would be merged with the override).
    let section = |key: &str| {
        let mut current = "";
        for l in &settings {
            if l.starts_with('[') {
                current = l;
            } else if l.starts_with(key) {
                return Some(current.to_string());
            }
        }
        None
    };
    assert_eq!(
        section("rustflags").as_deref(),
        Some("[target.x86_64-unknown-linux-gnu]"),
        ".cargo/config.toml: the x86-64-v2 rustflags belong to [target.x86_64-unknown-linux-gnu]"
    );
    assert!(
        settings.contains(&r#"rustflags = "-C target-cpu=x86-64-v2""#),
        ".cargo/config.toml: rustflags as a string, which the per-target variable replaces"
    );
    assert!(
        !settings.contains(&"[build]"),
        ".cargo/config.toml: no [build] section (its rustflags would reach every target)"
    );
    // The release keeps its explicit override and its ISA check.
    let release = read(&root.join(".github/workflows/release.yml"));
    assert!(
        release.contains(
            r#"CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS: "-C target-cpu=x86-64-v2""#
        )
    );
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
    let wf: support::yaml::Value = support::yaml::from_str(&text).expect("release.yml parses");
    let jobs = wf.get("jobs").expect("release.yml has jobs");
    let job_text = |name: &str| {
        support::yaml::to_string(jobs.get(name).unwrap_or_else(|| panic!("job {name}"))).unwrap()
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
    // Lot 354 (pre-alpha checks, F1-2): SHA256SUMS signed too, and checked
    // against the committed key, for a verification without gh.
    for needle in [
        "sign-rpm.sh sign",
        "sign-rpm.sh verify",
        "RPM-GPG-KEY-northnarrow.asc",
        "SHA256SUMS",
        "sign-rpm.sh sign-sums \"$fpr\" dist/SHA256SUMS",
        "sign-rpm.sh verify-sums \"$pub\" dist/SHA256SUMS",
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
    for job in ["sign", "publish"] {
        assert!(
            job_text(job).contains("a tag release without the signed SHA256SUMS"),
            "{job} must refuse a tag release without SHA256SUMS.asc"
        );
    }
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
        let wf: support::yaml::Value =
            support::yaml::from_str(&read(&file)).unwrap_or_else(|e| panic!("{}: {e}", rel(&file)));
        assert!(
            wf.get("jobs")
                .and_then(|j| j.as_mapping())
                .is_some_and(|m| !m.is_empty()),
            "{}: no jobs",
            rel(&file)
        );
    }
}

fn workflow_yaml(file: &Path) -> support::yaml::Value {
    support::yaml::from_str(&read(file)).unwrap_or_else(|e| panic!("{}: {e}", rel(file)))
}

/// The jobs of a workflow, by name.
fn jobs(wf: &support::yaml::Value) -> Vec<(String, support::yaml::Value)> {
    wf.get("jobs")
        .and_then(|j| j.as_mapping())
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.as_str().unwrap_or("?").to_string(), v.clone()))
                .collect()
        })
        .unwrap_or_default()
}

fn steps(job: &support::yaml::Value) -> Vec<support::yaml::Value> {
    job.get("steps")
        .and_then(|s| s.as_sequence())
        .cloned()
        .unwrap_or_default()
}

fn str_of<'a>(v: &'a support::yaml::Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(|x| x.as_str())
}

/// The write scopes a job may hold, by workflow and job (SUP-004).
const WRITE_ALLOWED: [(&str, &str, &str); 6] = [
    (".github/workflows/release.yml", "publish", "contents"),
    (".github/workflows/release.yml", "sign", "id-token"),
    (".github/workflows/release.yml", "sign", "attestations"),
    (".github/workflows/codeql.yml", "upload", "security-events"),
    // Lot M2, OpenSSF Scorecard: `analysis` uploads its SARIF to code
    // scanning, and signs the result it publishes to api.scorecard.dev
    // (the README's badge) with the job's OIDC token: the API checks that
    // the token was issued to this workflow of this repository.
    (
        ".github/workflows/scorecard.yml",
        "analysis",
        "security-events",
    ),
    (".github/workflows/scorecard.yml", "analysis", "id-token"),
];

/// Review of #496: a job that may write code-scanning results runs nothing
/// of the tree (with that token a build script or a proc-macro could upload
/// a SARIF or close alerts): no `run:` step, only these actions.
const UPLOAD_ONLY: [&str; 3] = [
    "actions/checkout@",
    "actions/download-artifact@",
    "github/codeql-action/upload-sarif@",
];

/// Lot M2: scorecard.yml's `analysis` also runs the Scorecard scanner, a
/// container action that reads the checked-out files and the GitHub API and
/// runs nothing of the tree, and keeps its SARIF as a run artifact. The
/// Scorecard API refuses a published result whose job runs anything else.
const SCORECARD_JOB: (&str, &str) = (".github/workflows/scorecard.yml", "analysis");
const SCORECARD_STEPS: [&str; 2] = ["ossf/scorecard-action@", "actions/upload-artifact@"];

/// The token problems of workflow `name`, one line each: a top level that is
/// not a read-only mapping, a job's write scope that WRITE_ALLOWED does not
/// list for that job, and a step of a code-scanning writer that is a `run:`
/// or an action the job may not run.
fn token_problems(name: &str, wf: &support::yaml::Value) -> Vec<String> {
    let mut bad = Vec::new();
    match wf.get("permissions").and_then(|p| p.as_mapping()) {
        None => bad.push(format!("{name}: no top-level `permissions:` mapping")),
        Some(m) => {
            for (scope, level) in m {
                let level = level.as_str().unwrap_or("?");
                if level != "read" && level != "none" {
                    bad.push(format!(
                        "{name}: top-level permission {}: {level}",
                        scope.as_str().unwrap_or("?")
                    ));
                }
            }
        }
    }
    for (job, body) in jobs(wf) {
        let Some(perms) = body.get("permissions") else {
            continue;
        };
        let Some(m) = perms.as_mapping() else {
            // `write-all` / `read-all`
            bad.push(format!("{name}: job {job}: permissions {perms:?}"));
            continue;
        };
        let scorecard = (name, job.as_str()) == SCORECARD_JOB;
        for (scope, level) in m {
            let scope = scope.as_str().unwrap_or("?");
            if level.as_str() == Some("write")
                && !WRITE_ALLOWED
                    .iter()
                    .any(|(f, j, s)| *f == name && *j == job && *s == scope)
            {
                bad.push(format!("{name}: job {job}: {scope}: write"));
            }
            if scope == "security-events" && level.as_str() == Some("write") {
                for step in steps(&body) {
                    let only = str_of(&step, "uses").is_some_and(|u| {
                        UPLOAD_ONLY.iter().any(|p| u.starts_with(p))
                            || (scorecard && SCORECARD_STEPS.iter().any(|p| u.starts_with(p)))
                    });
                    if step.get("run").is_some() || !only {
                        bad.push(format!(
                            "{name}: job {job} may write code-scanning results and runs {step:?}"
                        ));
                    }
                }
            }
        }
    }
    bad
}

/// SUP-004: without a `permissions:` block the token gets the repository's
/// default, which can be read/write. Every workflow starts read-only; a
/// job asks for more only where it publishes: release.yml's `publish`
/// writes the release, `sign` the attestations (SUP-024: never both),
/// codeql.yml's `upload` the code-scanning results (lot codeql), a job that
/// runs nothing of the tree (review of #496), and scorecard.yml's
/// `analysis` the Scorecard result and its SARIF (lot M2).
#[test]
fn every_workflow_token_is_read_only_unless_it_publishes() {
    let mut bad = Vec::new();
    for file in workflow_files() {
        bad.extend(token_problems(&rel(&file), &workflow_yaml(&file)));
    }
    assert!(
        bad.is_empty(),
        "workflow tokens must be read-only (write only where release.yml publishes, \
         codeql.yml uploads its results and scorecard.yml publishes its own):\n{}",
        bad.join("\n")
    );
}

/// Lot M2: the Scorecard job's two write scopes and its two extra actions
/// are its own. The same job under another workflow's name, a second job
/// of scorecard.yml, a `run:` step or another action in it, and the
/// scanner in codeql.yml's `upload` are each refused.
#[test]
fn the_token_check_keeps_the_scorecard_grants_to_its_job() {
    const SCORECARD: &str = ".github/workflows/scorecard.yml";
    const CODEQL: &str = ".github/workflows/codeql.yml";
    let root = repo_root();
    let scorecard = workflow_yaml(&root.join(SCORECARD));
    let codeql = workflow_yaml(&root.join(CODEQL));
    assert_eq!(token_problems(SCORECARD, &scorecard), Vec::<String>::new());
    assert_eq!(token_problems(CODEQL, &codeql), Vec::<String>::new());

    let has = |problems: &[String], needle: &str| problems.iter().any(|p| p.contains(needle));
    let job = |wf: &support::yaml::Value, name: &str| -> support::yaml::Value {
        wf.get("jobs")
            .and_then(|j| j.get(name))
            .cloned()
            .unwrap_or_else(|| panic!("job {name}"))
    };
    let with_job = |wf: &support::yaml::Value, name: &str, body: support::yaml::Value| {
        let mut wf = wf.clone();
        wf.get_mut("jobs")
            .and_then(|j| j.as_mapping_mut())
            .expect("jobs is a mapping")
            .insert(name.into(), body);
        wf
    };
    let with_step = |wf: &support::yaml::Value, name: &str, step: &str| {
        let mut body = job(wf, name);
        body.get_mut("steps")
            .and_then(|s| s.as_sequence_mut())
            .expect("steps")
            .push(support::yaml::from_str(step).expect("a step"));
        with_job(wf, name, body)
    };

    // the same workflow under another file name
    let p = token_problems(".github/workflows/ci.yml", &scorecard);
    assert!(has(&p, "job analysis: id-token: write"), "{p:?}");
    assert!(has(&p, "job analysis: security-events: write"), "{p:?}");
    // a second job of scorecard.yml with the same permissions
    let p = token_problems(
        SCORECARD,
        &with_job(&scorecard, "other", job(&scorecard, "analysis")),
    );
    assert!(has(&p, "job other: id-token: write"), "{p:?}");
    assert!(has(&p, "job other: security-events: write"), "{p:?}");
    assert!(!has(&p, "job analysis"), "{p:?}");
    // a `run:` step, or another action, in the Scorecard job
    let p = token_problems(
        SCORECARD,
        &with_step(&scorecard, "analysis", "run: cargo build"),
    );
    assert!(
        has(&p, "job analysis may write code-scanning results"),
        "{p:?}"
    );
    // an allowed action that also runs a command (GitHub refuses such a
    // step, the check does not count on it)
    let both =
        "{ uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1, run: cargo build }";
    let p = token_problems(SCORECARD, &with_step(&scorecard, "analysis", both));
    assert!(
        has(&p, "job analysis may write code-scanning results"),
        "{p:?}"
    );
    let other = "uses: actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9 # v6.1.0";
    let p = token_problems(SCORECARD, &with_step(&scorecard, "analysis", other));
    assert!(
        has(&p, "job analysis may write code-scanning results"),
        "{p:?}"
    );
    // the scanner and the artifact upload stay out of codeql.yml's upload
    for extra in SCORECARD_STEPS {
        let step = format!("uses: {extra}23f22cd43608bae7a1f1fa2603d7314dee9538a5 # v2.6.0");
        let p = token_problems(CODEQL, &with_step(&codeql, "upload", &step));
        assert!(
            has(&p, "job upload may write code-scanning results"),
            "{p:?}"
        );
    }
    // the Scorecard job's own permissions as `write-all` or `read-all`
    for all in ["write-all", "read-all"] {
        let mut body = job(&scorecard, "analysis");
        body.as_mapping_mut()
            .expect("a mapping")
            .insert("permissions".into(), all.into());
        let p = token_problems(SCORECARD, &with_job(&scorecard, "analysis", body));
        assert!(has(&p, "job analysis: permissions"), "{all}: {p:?}");
    }
    // a top level that grants anything is refused, `read-all` included
    // (a string, not a mapping)
    for top in ["read-all", "write-all", "{ id-token: write }"] {
        let mut wf = scorecard.clone();
        wf.as_mapping_mut()
            .expect("a mapping")
            .insert("permissions".into(), support::yaml::from_str(top).unwrap());
        assert!(
            !token_problems(SCORECARD, &wf).is_empty(),
            "top level {top}"
        );
    }
}

const SCORECARD_YML: &str = ".github/workflows/scorecard.yml";

/// The broken rules of a Scorecard workflow, one line each.
fn scorecard_problems(wf: &support::yaml::Value) -> Vec<String> {
    let mut bad = Vec::new();

    const EVENTS: [&str; 4] = [
        "push",
        "schedule",
        "branch_protection_rule",
        "workflow_dispatch",
    ];
    let on = wf
        .get("on")
        .and_then(|o| o.as_mapping())
        .cloned()
        .unwrap_or_default();
    let events: Vec<&str> = on.keys().filter_map(|k| k.as_str()).collect();
    for e in EVENTS {
        if !events.contains(&e) {
            bad.push(format!("no `on: {e}`"));
        }
    }
    for e in &events {
        if !EVENTS.contains(e) {
            bad.push(format!(
                "`on: {e}`: Scorecard publishes from the default branch only"
            ));
        }
    }
    let branches: Vec<&str> = on
        .get("push")
        .and_then(|p| p.get("branches"))
        .and_then(|b| b.as_sequence())
        .map(|s| s.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    if branches != ["main"] {
        bad.push(format!("on.push.branches {branches:?}, not [main]"));
    }
    let crons = on
        .get("schedule")
        .and_then(|s| s.as_sequence())
        .map(|s| s.iter().filter(|c| str_of(c, "cron").is_some()).count())
        .unwrap_or(0);
    if crons == 0 {
        bad.push("no `on.schedule` cron (the Maintained check)".to_string());
    }

    for key in ["env", "defaults"] {
        if wf.get(key).is_some() {
            bad.push(format!("a top-level `{key}`"));
        }
    }
    // the example's: no cache for the job that holds the OIDC token
    if str_of(wf, "cache-mode") != Some("none") {
        bad.push("no top-level `cache-mode: none`".to_string());
    }
    if !wf
        .get("permissions")
        .and_then(|p| p.as_mapping())
        .is_some_and(|m| m.is_empty())
    {
        bad.push(format!(
            "top-level permissions {:?}, not `{{}}`",
            wf.get("permissions")
        ));
    }

    let jobs = jobs(wf);
    let names: Vec<&str> = jobs.iter().map(|(n, _)| n.as_str()).collect();
    if names != ["analysis"] {
        bad.push(format!("jobs {names:?}, not the one `analysis`"));
    }
    let Some((_, job)) = jobs.iter().find(|(n, _)| n == "analysis") else {
        return bad;
    };
    let perms: Vec<(String, String)> = string_pairs(job.get("permissions"));
    if perms != pairs(&[("security-events", "write"), ("id-token", "write")]) {
        bad.push(format!("analysis: permissions {perms:?}"));
    }
    for key in ["env", "defaults", "container", "services", "strategy"] {
        if job.get(key).is_some() {
            bad.push(format!("analysis: has `{key}`"));
        }
    }
    if str_of(job, "runs-on") != Some("ubuntu-latest") {
        bad.push(format!("analysis: runs-on {:?}", job.get("runs-on")));
    }
    if !str_of(job, "if")
        .is_some_and(|c| c.contains("github.event.repository.default_branch == github.ref_name"))
    {
        bad.push(format!("analysis: if {:?}", job.get("if")));
    }

    const STEPS: [&str; 4] = [
        "actions/checkout@",
        "ossf/scorecard-action@",
        "actions/upload-artifact@",
        "github/codeql-action/upload-sarif@",
    ];
    let steps = steps(job);
    let uses: Vec<&str> = steps.iter().filter_map(|s| str_of(s, "uses")).collect();
    let in_order =
        uses.len() == STEPS.len() && uses.iter().zip(STEPS).all(|(u, p)| u.starts_with(p));
    if steps.len() != STEPS.len() || !in_order {
        bad.push(format!("analysis: steps {uses:?}, not {STEPS:?}"));
    }
    for step in &steps {
        if step.get("run").is_some() || step.get("env").is_some() {
            bad.push(format!("analysis: a step with `run`/`env`: {step:?}"));
        }
    }
    let with_of = |prefix: &str| {
        steps
            .iter()
            .find(|s| str_of(s, "uses").is_some_and(|u| u.starts_with(prefix)))
            .and_then(|s| s.get("with"))
            .cloned()
            .unwrap_or_default()
    };
    let scan = with_of("ossf/scorecard-action@");
    let yes = |v: &support::yaml::Value, key: &str| {
        v.get(key)
            .is_some_and(|x| x.as_bool() == Some(true) || x.as_str() == Some("true"))
    };
    for key in ["publish_results", "fail_on_publish_error"] {
        if !yes(&scan, key) {
            bad.push(format!("scorecard-action: `{key}: true` is missing"));
        }
    }
    if str_of(&scan, "results_format") != Some("sarif") {
        bad.push("scorecard-action: `results_format: sarif` is missing".to_string());
    }
    let results = str_of(&scan, "results_file").unwrap_or("?");
    if str_of(&with_of("github/codeql-action/upload-sarif@"), "sarif_file") != Some(results) {
        bad.push(format!("upload-sarif: `sarif_file` is not {results}"));
    }
    if str_of(&with_of("actions/upload-artifact@"), "path") != Some(results) {
        bad.push(format!("upload-artifact: `path` is not {results}"));
    }

    bad
}

/// Lot M2: scorecard.yml publishes the OpenSSF Scorecard result behind the
/// README's badge. The Scorecard API accepts a result only from a workflow
/// that keeps its rules (scorecard-action's "Workflow restrictions": no
/// top-level env, defaults or write; one job with the OIDC token, without
/// env, defaults, container or services, on a hosted Ubuntu runner, whose
/// steps are approved actions only), and the job's write scopes are for that
/// publish alone. Its triggers, its one job and the job's steps stay as they
/// are.
#[test]
fn scorecard_publishes_from_one_job_that_runs_only_its_scanner() {
    let bad = scorecard_problems(&workflow_yaml(&repo_root().join(SCORECARD_YML)));
    assert!(
        bad.is_empty(),
        "{SCORECARD_YML} breaks the rules of a published Scorecard result:\n{}",
        bad.join("\n")
    );
}

/// Lot M2: each rule of `scorecard_problems`, broken in a copy of
/// scorecard.yml, is reported.
#[test]
fn the_scorecard_check_refuses_each_broken_rule() {
    let text = read(&repo_root().join(SCORECARD_YML));
    let checkout = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1";
    let scanner = "ossf/scorecard-action@23f22cd43608bae7a1f1fa2603d7314dee9538a5 # v2.6.0";
    let swapped = text
        .replace(checkout, "\u{0}")
        .replace(scanner, checkout)
        .replace('\u{0}', scanner);
    let second_job = format!(
        "{text}  other:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: {checkout}\n"
    );
    let planted: Vec<(String, &str)> = vec![
        (swapped, "analysis: steps"),
        (second_job, "jobs [\"analysis\", \"other\"]"),
    ];
    let edits: [(&str, &str, &str); 21] = [
        (
            "  workflow_dispatch:\n",
            "  workflow_dispatch:\n  pull_request_target:\n",
            "`on: pull_request_target`",
        ),
        ("  workflow_dispatch:\n", "", "no `on: workflow_dispatch`"),
        (
            "    branches: [main]\n",
            "    branches: [main, dev]\n",
            "on.push.branches",
        ),
        ("    - cron: ", "    - crom: ", "no `on.schedule` cron"),
        (
            "permissions: {}\n",
            "permissions: {}\nenv:\n  A: b\n",
            "a top-level `env`",
        ),
        (
            "permissions: {}\n",
            "permissions: {}\ndefaults:\n  run:\n    shell: bash\n",
            "a top-level `defaults`",
        ),
        (
            "permissions: {}\n",
            "permissions: read-all\n",
            "top-level permissions",
        ),
        ("cache-mode: none\n", "", "`cache-mode: none`"),
        (
            "permissions: {}\n",
            "permissions:\n  contents: read\n",
            "top-level permissions",
        ),
        (
            "    timeout-minutes: 15\n",
            "    timeout-minutes: 15\n    env:\n      A: b\n",
            "analysis: has `env`",
        ),
        (
            "    timeout-minutes: 15\n",
            "    timeout-minutes: 15\n    container: ubuntu:24.04\n",
            "analysis: has `container`",
        ),
        (
            "    runs-on: ubuntu-latest\n",
            "    runs-on: self-hosted\n",
            "analysis: runs-on",
        ),
        (
            "    if: ${{ github.event.repository.default_branch == github.ref_name }}\n",
            "",
            "analysis: if",
        ),
        (
            "      id-token: write",
            "      contents: write\n      id-token: write",
            "analysis: permissions",
        ),
        (
            "          publish_results: true\n",
            "          publish_results: false\n",
            "`publish_results: true` is missing",
        ),
        (
            "          fail_on_publish_error: true\n",
            "",
            "`fail_on_publish_error: true` is missing",
        ),
        (
            "          results_format: sarif\n",
            "          results_format: json\n",
            "`results_format: sarif` is missing",
        ),
        (
            "          sarif_file: results.sarif\n",
            "          sarif_file: other.sarif\n",
            "upload-sarif: `sarif_file`",
        ),
        (
            "          path: results.sarif\n",
            "          path: other.sarif\n",
            "upload-artifact: `path`",
        ),
        (
            "      - name: Run analysis\n",
            "      - run: echo planted\n      - name: Run analysis\n",
            "a step with `run`/`env`",
        ),
        (
            "          persist-credentials: false\n",
            "          persist-credentials: false\n        env:\n          A: b\n",
            "a step with `run`/`env`",
        ),
    ];
    let mut cases = planted;
    for (from, to, want) in edits {
        assert_eq!(
            text.matches(from).count(),
            1,
            "`{from}` once in {SCORECARD_YML}"
        );
        cases.push((text.replace(from, to), want));
    }
    for (planted, want) in &cases {
        let wf: support::yaml::Value = support::yaml::from_str(planted).expect("planted YAML");
        let p = scorecard_problems(&wf);
        assert!(
            p.iter().any(|l| l.contains(want)),
            "`{want}` not reported: {p:?}"
        );
    }
}

/// SUP-004: actions/checkout writes the token into .git/config unless told
/// not to, and every build script and proc-macro the job compiles can read
/// it there. No job here pushes.
#[test]
fn no_checkout_persists_the_token() {
    let mut seen = 0;
    let mut bad = Vec::new();
    for file in workflow_files() {
        let wf = workflow_yaml(&file);
        for (job, body) in jobs(&wf) {
            for step in steps(&body) {
                if !str_of(&step, "uses").is_some_and(|u| u.starts_with("actions/checkout@")) {
                    continue;
                }
                seen += 1;
                let persist = step.get("with").and_then(|w| w.get("persist-credentials"));
                let off = persist
                    .is_some_and(|p| p.as_bool() == Some(false) || p.as_str() == Some("false"));
                if !off {
                    bad.push(format!("{}: job {job}", rel(&file)));
                }
            }
        }
    }
    assert!(seen > 0, "no actions/checkout step found");
    assert!(
        bad.is_empty(),
        "every actions/checkout needs `persist-credentials: false`:\n{}",
        bad.join("\n")
    );
}

/// SUP-022: a restore key is a prefix match. `${{ runner.os }}-cargo-`
/// restored any job's cache — another job's `target/`, built with other
/// features or toolchains — into this one. A restore key may only drop the
/// hash from the end of the job's own key, or the run id from the end of a
/// rolling one (the fuzz corpus, SUP-018: saved by every run, restored
/// from the latest).
#[test]
fn cache_restore_keys_stay_within_their_own_key() {
    let mut seen = 0;
    let mut bad = Vec::new();
    for file in workflow_files() {
        let wf = workflow_yaml(&file);
        for (job, body) in jobs(&wf) {
            for step in steps(&body) {
                if !str_of(&step, "uses").is_some_and(|u| u.starts_with("actions/cache@")) {
                    continue;
                }
                let with = step.get("with");
                let key = with.and_then(|w| str_of(w, "key")).unwrap_or("");
                let Some(restore) = with.and_then(|w| str_of(w, "restore-keys")) else {
                    continue;
                };
                let own = key
                    .rfind("${{ hashFiles(")
                    .or_else(|| key.strip_suffix("${{ github.run_id }}").map(str::len))
                    .map(|i| &key[..i]);
                for entry in restore.lines().map(str::trim).filter(|l| !l.is_empty()) {
                    seen += 1;
                    if own != Some(entry) {
                        bad.push(format!(
                            "{}: job {job}: restore key `{entry}` (key `{key}`)",
                            rel(&file)
                        ));
                    }
                }
            }
        }
    }
    assert!(seen > 0, "no restore-keys entry found");
    assert!(
        bad.is_empty(),
        "a restore key must be its own key without the trailing hashFiles():\n{}",
        bad.join("\n")
    );
}

/// Lot 397 (Rust 1.100.0): a cached `target/` is only of use to the
/// toolchain that built it, and the cache key named the lockfiles and
/// manifests alone. A toolchain bump left them unchanged, so the key hit
/// exactly: every run restored the old compiler's artifacts, rebuilt all
/// of them, and never saved (an exact hit is not saved) until the next
/// dependency change. With 1.100's new build-dir layout the restored tree
/// also stayed beside the new one. A step that caches `<dir>/target` keys on
/// `<dir>/rust-toolchain.toml` when there is one, before the trailing
/// hashFiles(), so its restore key (the key without it) keys on it too.
#[test]
fn a_cached_target_is_keyed_on_its_toolchain() {
    let mut seen = 0;
    let mut bad = Vec::new();
    for file in workflow_files() {
        let wf = workflow_yaml(&file);
        for (job, body) in jobs(&wf) {
            for step in steps(&body) {
                if !str_of(&step, "uses").is_some_and(|u| u.starts_with("actions/cache@")) {
                    continue;
                }
                let with = step.get("with");
                let key = with.and_then(|w| str_of(w, "key")).unwrap_or("");
                let own = key.rfind("${{ hashFiles(").map_or("", |i| &key[..i]);
                let paths = with.and_then(|w| str_of(w, "path")).unwrap_or("");
                for path in paths.lines().map(str::trim) {
                    let Some(dir) = path
                        .strip_suffix("target")
                        .filter(|d| d.is_empty() || d.ends_with('/'))
                    else {
                        continue;
                    };
                    let toolchain = format!("{dir}rust-toolchain.toml");
                    if !repo_root().join(&toolchain).is_file() {
                        continue;
                    }
                    seen += 1;
                    if !own.contains(&format!("'{toolchain}'")) {
                        bad.push(format!(
                            "{}: job {job}: caches {path}, key `{key}` does not hash \
                             {toolchain} before its last hashFiles()",
                            rel(&file)
                        ));
                    }
                }
            }
        }
    }
    assert!(seen > 0, "no cached target/ found");
    assert!(
        bad.is_empty(),
        "a cached target/ must be keyed on the toolchain that builds it:\n{}",
        bad.join("\n")
    );
}

/// Logical lines of a shell script: continuations joined, comments dropped.
fn script_lines(script: &str) -> Vec<String> {
    let lines: Vec<&str> = script.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let mut cmd = String::new();
        loop {
            let l = lines[i].trim_end();
            cmd.push_str(l.trim_end_matches('\\'));
            cmd.push(' ');
            i += 1;
            if !l.ends_with('\\') || i >= lines.len() {
                break;
            }
        }
        let t = cmd.trim_start();
        if t.starts_with('#') {
            continue;
        }
        let code = match t.find(" # ") {
            Some(at) => &t[..at],
            None => t,
        };
        out.push(code.to_string());
    }
    out
}

/// A cargo invocation in a shell script.
#[derive(Debug)]
struct CargoCall {
    /// `+toolchain` and flags before the subcommand.
    global: Vec<String>,
    sub: String,
    /// The arguments up to the next shell separator, without what follows `--`.
    args: Vec<String>,
    line: String,
}

impl CargoCall {
    fn locked_before(flags: &[String]) -> bool {
        flags.iter().any(|f| f == "--locked" || f == "--frozen")
    }
    fn global_locked(&self) -> bool {
        Self::locked_before(&self.global)
    }
    fn locked(&self) -> bool {
        self.global_locked() || Self::locked_before(&self.args)
    }
}

fn cargo_calls(script: &str) -> Vec<CargoCall> {
    let mut out = Vec::new();
    for line in script_lines(script) {
        let mut flat = line.clone();
        for sep in ["&&", "||", "$(", ";", "|", "(", ")", "`"] {
            flat = flat.replace(sep, "\n");
        }
        for segment in flat.lines() {
            let tokens: Vec<&str> = segment.split_whitespace().collect();
            let Some(at) = tokens.iter().position(|t| *t == "cargo") else {
                continue;
            };
            let mut global = Vec::new();
            let mut rest = tokens[at + 1..].iter();
            let mut sub = None;
            for t in rest.by_ref() {
                if t.starts_with('+') || t.starts_with('-') {
                    global.push(t.to_string());
                } else {
                    sub = Some(t.to_string());
                    break;
                }
            }
            let Some(sub) = sub else { continue };
            let args = rest
                .take_while(|t| **t != "--")
                .map(|t| t.to_string())
                .collect();
            out.push(CargoCall {
                global,
                sub,
                args,
                line: line.trim().to_string(),
            });
        }
    }
    out
}

/// SUP-016: without `--locked`, cargo resolves a manifest change again on
/// the runner and builds whatever the registry serves that day, while the
/// audit job checks the committed lockfile. Every build, test, clippy,
/// check, run, fetch and tree is locked; `cargo xtask` twice (xtask's own
/// build, and the nested builds xtask runs with a cleared environment).
/// cargo-fuzz and cargo-kani have no `--locked`: their job checks the
/// lockfile first (`fetch --locked`) and that nothing changed it after.
#[test]
fn every_workflow_build_is_locked() {
    const LOCKED: [&str; 9] = [
        "build", "check", "clippy", "test", "run", "fetch", "tree", "doc", "bench",
    ];
    const NO_BUILD: [&str; 4] = ["fmt", "install", "audit", "cyclonedx"];
    let mut seen = 0;
    let mut bad = Vec::new();
    for file in workflow_files() {
        let wf = workflow_yaml(&file);
        for (job, body) in jobs(&wf) {
            let runs: Vec<String> = steps(&body)
                .iter()
                .map(|s| str_of(s, "run").unwrap_or("").to_string())
                .collect();
            for (i, run) in runs.iter().enumerate() {
                for call in cargo_calls(run) {
                    let at = format!("{}: job {job}: {}", rel(&file), call.line);
                    let sub = call.sub.as_str();
                    if LOCKED.contains(&sub) {
                        seen += 1;
                        if !call.locked() {
                            bad.push(format!("{at} (no --locked)"));
                        }
                    } else if sub == "xtask" {
                        seen += 1;
                        if !call.global_locked() || !CargoCall::locked_before(&call.args) {
                            bad.push(format!("{at} (needs `cargo --locked xtask … --locked`)"));
                        }
                    } else if sub == "fuzz" || sub == "kani" {
                        seen += 1;
                        let lock = if sub == "fuzz" {
                            "fuzz/Cargo.lock"
                        } else {
                            "Cargo.lock"
                        };
                        let fetched = runs[..i].iter().any(|r| {
                            cargo_calls(r)
                                .iter()
                                .any(|c| c.sub == "fetch" && c.locked())
                                && (sub != "fuzz" || r.contains("fuzz"))
                        });
                        let unchanged = runs[i + 1..]
                            .iter()
                            .any(|r| r.contains("git diff --exit-code") && r.contains(lock));
                        if !fetched || !unchanged {
                            bad.push(format!(
                                "{at} (cargo {sub} has no --locked: the job needs an earlier \
                                 `fetch --locked` of its lockfile and a later \
                                 `git diff --exit-code -- … {lock}`)"
                            ));
                        }
                    } else if !NO_BUILD.contains(&sub) {
                        bad.push(format!(
                            "{at} (cargo {sub}: unknown here; add it to LOCKED or NO_BUILD)"
                        ));
                    }
                }
            }
        }
    }
    assert!(
        seen >= 20,
        "expected the workflows' cargo builds, found {seen}"
    );
    assert!(
        bad.is_empty(),
        "every cargo build in the workflows must be --locked:\n{}",
        bad.join("\n")
    );
}

/// `MAJOR.MINOR[.PATCH]` as numbers.
fn rust_version(s: &str) -> Option<(u64, u64, u64)> {
    let parts: Vec<u64> = s
        .split('.')
        .map(|p| p.parse().ok())
        .collect::<Option<_>>()?;
    match parts[..] {
        [a, b] => Some((a, b, 0)),
        [a, b, c] => Some((a, b, c)),
        _ => None,
    }
}

/// The value of `key = "…"` in `[section]` of a small TOML file.
fn toml_string(text: &str, section: &str, key: &str) -> Option<String> {
    let mut current = String::new();
    for line in text.lines() {
        let l = line.split('#').next().unwrap_or("").trim();
        if l.starts_with('[') {
            current = l.trim_matches(|c| c == '[' || c == ']').trim().to_string();
            continue;
        }
        if current != section {
            continue;
        }
        if let Some((k, v)) = l.split_once('=') {
            if k.trim() == key {
                return Some(v.trim().trim_matches('"').to_string());
            }
        }
    }
    None
}

fn declared_rust_version() -> (String, (u64, u64, u64)) {
    let text = read(&repo_root().join("Cargo.toml"));
    let v = toml_string(&text, "workspace.package", "rust-version")
        .expect("Cargo.toml [workspace.package] declares rust-version");
    let parsed = rust_version(&v).unwrap_or_else(|| panic!("rust-version `{v}` is not a version"));
    (v, parsed)
}

/// SUP-015: `channel = "stable"` built every PR with whatever stable was
/// that day, and `rust-version` claimed a floor nothing checked (1.83, while
/// the locked uuid needs 1.89). The toolchain is a fixed release, no
/// workflow installs a moving one, the floor is at most the pin, the `msrv`
/// CI job builds with the floor, and Dependabot proposes the next release.
#[test]
fn the_toolchain_is_pinned_and_the_msrv_is_checked() {
    let root = repo_root();
    let toolchain = read(&root.join("rust-toolchain.toml"));
    let channel = toml_string(&toolchain, "toolchain", "channel")
        .expect("rust-toolchain.toml names a channel");
    let pinned = rust_version(&channel)
        .filter(|_| channel.split('.').count() == 3)
        .unwrap_or_else(|| {
            panic!("rust-toolchain.toml must pin a release (`1.x.y`), not `{channel}`")
        });
    let (declared, floor) = declared_rust_version();
    assert!(
        floor <= pinned,
        "rust-version {declared} is newer than the pinned toolchain {channel}"
    );

    let mut bad = Vec::new();
    for file in workflow_files() {
        for (n, line) in read(&file).lines().enumerate() {
            let code = line.split(" #").next().unwrap_or("");
            if code.trim_start().starts_with('#') {
                continue;
            }
            if [
                "install stable",
                "default stable",
                "+stable",
                "@stable",
                "toolchain: stable",
            ]
            .iter()
            .any(|m| code.contains(m))
            {
                bad.push(format!("{}:{}: {}", rel(&file), n + 1, line.trim()));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "workflows must build with the pinned toolchain, not `stable`:\n{}",
        bad.join("\n")
    );

    let ci = workflow_yaml(&root.join(".github/workflows/ci.yml"));
    let msrv_job = jobs(&ci).into_iter().find(|(_, body)| {
        let runs: Vec<String> = steps(body)
            .iter()
            .filter_map(|s| str_of(s, "run").map(str::to_string))
            .collect();
        let reads_floor = runs
            .iter()
            .any(|r| r.contains("rust-version") && r.contains("Cargo.toml"));
        let checks = runs.iter().any(|r| {
            cargo_calls(r).iter().any(|c| {
                c.sub == "check"
                    && c.locked()
                    && c.global.iter().any(|g| g.starts_with('+'))
                    && c.args.iter().any(|a| a == "--workspace")
            })
        });
        reads_floor && checks
    });
    assert!(
        msrv_job.is_some(),
        "ci.yml needs a job that reads rust-version from Cargo.toml and runs \
         `cargo +<it> check --workspace --locked`"
    );

    let dependabot: support::yaml::Value =
        support::yaml::from_str(&read(&root.join(".github/dependabot.yml"))).unwrap();
    let toolchain_updates = dependabot
        .get("updates")
        .and_then(|u| u.as_sequence())
        .is_some_and(|u| {
            u.iter().any(|e| {
                str_of(e, "package-ecosystem") == Some("rust-toolchain")
                    && str_of(e, "directory") == Some("/")
            })
        });
    assert!(
        toolchain_updates,
        ".github/dependabot.yml must propose rust-toolchain.toml bumps (rust-toolchain, /)"
    );
}

/// The dated nightlies `nightly-YYYY-MM-DD` that `line` names.
fn dated_nightlies(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = line[from..].find("nightly-") {
        let start = from + at;
        let date = &line.as_bytes()[start + "nightly-".len()..];
        let dated = date.len() >= 10
            && date[..10].iter().enumerate().all(|(i, b)| match i {
                4 | 7 => *b == b'-',
                _ => b.is_ascii_digit(),
            });
        if dated {
            out.push(&line[start..start + "nightly-".len() + 10]);
        }
        from = start + "nightly-".len();
    }
    out
}

/// The lines of the job `name` of a workflow's text: from its key, two
/// spaces in under `jobs:`, to the next job's key.
fn job_lines<'a>(text: &'a str, name: &str) -> Vec<(usize, &'a str)> {
    let key = format!("  {name}:");
    let mut out = Vec::new();
    let mut inside = false;
    for (i, line) in text.lines().enumerate() {
        let job_key = line.starts_with("  ")
            && !line[2..].starts_with([' ', '#'])
            && line.trim_end().ends_with(':');
        if job_key {
            inside = line.trim_end() == key;
        } else if line.starts_with(|c: char| c.is_ascii_alphanumeric()) {
            inside = false; // a top-level key after `jobs:`
        }
        if inside {
            out.push((i, line));
        }
    }
    out
}

/// Lot 400a: two dated nightlies, each one channel. The eBPF crate's, the
/// one of `agent-ebpf/rust-toolchain.toml`: the ebpf-build, release and lab
/// VM jobs install it, so the object CI and the release build is the one
/// the lab measured with that compiler; a job left on another date builds
/// another object. The fuzz job's own: its harness builds the agent, whose
/// aya 0.16 and aya-obj 0.6 need rustc 1.98 — lot 400a moved the fuzz job
/// alone, from the eBPF nightly's 1.93; lot 1.2 (400b) moved the eBPF
/// crate's with aya-ebpf 0.3, to the same date (one download serves both
/// on a runner), and the two may move apart again. Every dated nightly of
/// the fuzz job (install,
/// lockfile check, build, list) is the fuzz channel, and the fuzz README
/// names that one; every other dated nightly of the workflows and the CI
/// scripts is the eBPF crate's.
#[test]
fn every_dated_nightly_is_its_jobs_channel() {
    let root = repo_root();
    let ebpf = toml_string(
        &read(&root.join("agent-ebpf/rust-toolchain.toml")),
        "toolchain",
        "channel",
    )
    .expect("agent-ebpf/rust-toolchain.toml [toolchain] channel");
    assert_eq!(
        dated_nightlies(&ebpf),
        vec![ebpf.as_str()],
        "the eBPF crate's channel is a dated nightly: {ebpf}"
    );

    // the fuzz job: the one ci.yml job that runs `cargo +<nightly> fuzz build`
    let ci_path = root.join(".github/workflows/ci.yml");
    let ci_text = read(&ci_path);
    let fuzz_jobs: Vec<String> = jobs(&workflow_yaml(&ci_path))
        .into_iter()
        .filter(|(_, body)| {
            steps(body)
                .iter()
                .filter_map(|s| str_of(s, "run"))
                .any(|r| {
                    r.lines()
                        .any(|l| l.contains("cargo +") && l.contains(" fuzz build"))
                })
        })
        .map(|(name, _)| name)
        .collect();
    assert_eq!(
        fuzz_jobs.len(),
        1,
        "one ci.yml job builds the fuzz targets: {fuzz_jobs:?}"
    );
    let fuzz_lines = job_lines(&ci_text, &fuzz_jobs[0]);
    let mut in_fuzz_job: Vec<&str> = fuzz_lines
        .iter()
        .flat_map(|(_, l)| dated_nightlies(l))
        .collect();
    // install, the lockfile check, build, list
    assert!(
        in_fuzz_job.len() >= 4,
        "only {} dated nightlies in ci.yml's {} job",
        in_fuzz_job.len(),
        fuzz_jobs[0]
    );
    in_fuzz_job.sort_unstable();
    in_fuzz_job.dedup();
    assert_eq!(
        in_fuzz_job.len(),
        1,
        "ci.yml's {} job names one nightly: {in_fuzz_job:?}",
        fuzz_jobs[0]
    );
    let fuzz = in_fuzz_job[0].to_string();
    let fuzz_rows: std::collections::BTreeSet<usize> = fuzz_lines.iter().map(|(i, _)| *i).collect();

    let mut files = workflow_files();
    files.extend(files_under(&root.join(".github/scripts"), &[".sh"], &[]));
    files.push(root.join("fuzz/README.md"));
    let mut named_ebpf = 0;
    let mut bad = Vec::new();
    for f in &files {
        let fuzz_side = f.ends_with("fuzz/README.md");
        for (i, line) in read(f).lines().enumerate() {
            let ebpf_side = !fuzz_side && !(*f == ci_path && fuzz_rows.contains(&i));
            let channel = if ebpf_side { &ebpf } else { &fuzz };
            for n in dated_nightlies(line) {
                if n != channel {
                    bad.push(format!("{}:{}: {n} (expected {channel})", rel(f), i + 1));
                } else if ebpf_side {
                    named_ebpf += 1;
                }
            }
        }
    }
    // ci.yml's ebpf-build job, release.yml, lab-vm.yml
    assert!(
        named_ebpf >= 3,
        "only {named_ebpf} lines name the eBPF crate's nightly {ebpf} outside the fuzz job"
    );
    assert!(
        bad.is_empty(),
        "dated nightlies off their channel (eBPF: agent-ebpf/rust-toolchain.toml's {ebpf}; \
         the fuzz job and fuzz/README.md: {fuzz}):\n{}",
        bad.join("\n")
    );
    // the readers themselves
    assert_eq!(
        dated_nightlies("cargo +nightly-2025-12-01 fuzz build # nightly, nightly-2026"),
        vec!["nightly-2025-12-01"]
    );
    let wf = "jobs:\n  a:\n    x: nightly-2025-12-01\n  # c:\n  fuzz:\n    y: 1\n\n    # z\n  b:\n";
    let rows = |wf: &str| {
        job_lines(wf, "fuzz")
            .iter()
            .map(|(i, _)| *i)
            .collect::<Vec<_>>()
    };
    assert_eq!(rows(wf), vec![4, 5, 6, 7]);
    assert_eq!(
        rows("jobs:\n  fuzz:\n    y: 1\nenv:\n  fuzz: 2\n"),
        vec![1, 2]
    );
}

/// Lot 1.2 (F16): the eBPF object CI tests is kept, and every other build
/// of it names its own. ci.yml's ebpf-build job writes the object's sha256
/// after the build and its checks, and uploads the object with its build
/// stamp and that sha256 (artefact `ebpf-object`), the one CI tested.
/// release.yml's package job rebuilds the object and prints the sha256 of
/// the one it embeds, and lab-vm.yml's guest job keeps the sha256 of the
/// one its guest loads in its evidence. The lab does not load the
/// artefact: `nn-lab.sh sync` rebuilds the object on the host and
/// `verifier-check synced` loads the guest's synced copy (its report names
/// the sha256). Loading the artefact there and checking its sha256 is lot
/// 1.10's. All three build it alike: the nightly is one channel
/// (`every_dated_nightly_is_its_jobs_channel`), and every `cargo install
/// bpf-linker` of the workflows pins one version, the one xtask's and the
/// lab's hints name. The gap, documented in release.yml: the release
/// rebuilds the object (a build is reproducible: two clean builds of one
/// tree at one path give one sha256), and nothing compares its sha256 with
/// the artefact's but a maintainer by hand — the package job holds no
/// token that reads another run's artefacts (SUP-003).
#[test]
fn the_ebpf_object_ci_tests_is_kept_and_every_build_names_its_own() {
    const OBJ: &str = "agent-ebpf/target/bpfel-unknown-none/release/northnarrow-agent-ebpf";
    let root = repo_root();
    let job = |file: &str, name: &str| -> Vec<support::yaml::Value> {
        let wf = workflow_yaml(&root.join(".github/workflows").join(file));
        let (_, j) = jobs(&wf)
            .into_iter()
            .find(|(n, _)| n == name)
            .unwrap_or_else(|| panic!("{file}: no job {name}"));
        steps(&j)
    };
    let run = |s: &support::yaml::Value| str_of(s, "run").unwrap_or("").to_string();
    let at =
        |steps: &[support::yaml::Value], what: &str, f: &dyn Fn(&support::yaml::Value) -> bool| {
            steps
                .iter()
                .position(f)
                .unwrap_or_else(|| panic!("no step that {what}"))
        };

    // ci.yml's ebpf-build: the build, its checks, the sha256, the upload
    let ci = job("ci.yml", "ebpf-build");
    let build = at(&ci, "builds the object", &|s| {
        run(s).contains("xtask build-ebpf --locked")
    });
    let checks = at(&ci, "checks the back-edges", &|s| {
        run(s).contains("no_function_has_a_back_edge_the_5_15_verifier_rejects")
    });
    let sha = at(&ci, "writes the sha256", &|s| {
        run(s).contains("sha256sum northnarrow-agent-ebpf > northnarrow-agent-ebpf.sha256")
    });
    assert!(
        run(&ci[sha]).starts_with("cd agent-ebpf/target/bpfel-unknown-none/release\n")
            && run(&ci[sha]).contains("$GITHUB_STEP_SUMMARY"),
        "the sha256 written next to the object and named in the job summary"
    );
    let up = at(&ci, "uploads it", &|s| {
        str_of(s, "uses").is_some_and(|u| u.starts_with("actions/upload-artifact@"))
    });
    assert!(
        build < checks && checks < sha && sha < up,
        "built, checked, hashed, uploaded: {build} {checks} {sha} {up}"
    );
    let with = ci[up].get("with").expect("the upload's `with`");
    assert_eq!(str_of(with, "name"), Some("ebpf-object"));
    assert_eq!(str_of(with, "if-no-files-found"), Some("error"));
    let paths: Vec<String> = str_of(with, "path")
        .unwrap_or("")
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(
        paths,
        vec![
            OBJ.to_string(),
            format!("{OBJ}.buildhash"),
            format!("{OBJ}.sha256")
        ],
        "the object, its build stamp and its sha256"
    );

    // the release's package job: built, then the embedded object's sha256
    let pkg = job("release.yml", "package");
    let built = at(&pkg, "builds the release", &|s| {
        run(s).contains("xtask build --release --locked")
    });
    let named = at(&pkg, "prints the object's sha256", &|s| {
        run(s).contains(&format!("sha256sum {OBJ}")) && run(s).contains("$GITHUB_STEP_SUMMARY")
    });
    assert!(built < named);

    // lab-vm.yml's guest: the object built on the host, its sha256 kept
    let guest = job("lab-vm.yml", "guest");
    let host = at(&guest, "builds the object on the host", &|s| {
        run(s).contains("cargo --locked xtask build-ebpf --locked")
    });
    assert!(
        run(&guest[host]).contains(&format!(
            "sha256sum {OBJ} | tee \"$GATE_OUT/ebpf-object.sha256\""
        )),
        "the guest's evidence names the object it loads"
    );

    // one bpf-linker: every install in the workflows, whatever the order of
    // its flags (the review of #618), and the hints
    let mut versions = std::collections::BTreeSet::new();
    let mut installs = 0;
    for f in workflow_files() {
        for line in shell_lines(&read(&f)) {
            if !line.contains("bpf-linker") {
                continue;
            }
            // a line that names bpf-linker and does not `cargo install` it
            // (binstall, a download) would be one more bpf-linker
            let pins = cargo_install_pins_on(&line, "bpf-linker");
            assert!(
                !pins.is_empty(),
                "{}: bpf-linker outside a `cargo install` of it: {}",
                rel(&f),
                line.trim()
            );
            installs += pins.len();
            versions.extend(pins);
        }
    }
    assert!(installs >= 3, "ci.yml, release.yml, lab-vm.yml: {installs}");
    assert_eq!(
        versions.len(),
        1,
        "one bpf-linker in the workflows: {versions:?}"
    );
    let v = versions.into_iter().next().unwrap();
    assert!(
        v.split('.').count() == 3 && v.split('.').all(|n| n.parse::<u32>().is_ok()),
        "bpf-linker pinned to one exact version: {v}"
    );
    for hint in ["xtask/src/main.rs", "deploy/lab/nn-lab.sh"] {
        assert!(
            read(&root.join(hint))
                .contains(&format!("cargo install bpf-linker --version {v} --locked")),
            "{hint} names bpf-linker {v}"
        );
    }
}

/// A shell's two quotes, double and single, the double one spelled as its
/// code point: `path_liveness.rs` reads this file's string literals by
/// their double quotes, and a bare one in a char literal shifts them.
const QUOTES: [char; 2] = ['\u{22}', '\''];

/// The lines of a workflow or script as the shell reads them: a trailing
/// `\` joins the next line; a `#` comment (a `#` that starts a word,
/// outside quotes) and a YAML step's `name:` are dropped.
fn shell_lines(text: &str) -> Vec<String> {
    let uncommented = |line: &str| -> String {
        let (mut quote, mut prev) = (None, ' ');
        for (at, c) in line.char_indices() {
            match (quote, c) {
                (None, '#') if prev.is_whitespace() => return line[..at].to_string(),
                (None, c) if QUOTES.contains(&c) => quote = Some(c),
                (Some(q), _) if c == q => quote = None,
                _ => {}
            }
            prev = c;
        }
        line.to_string()
    };
    let mut out = Vec::new();
    let mut cur = String::new();
    for raw in text.lines() {
        let line = uncommented(raw);
        if line
            .trim_start()
            .trim_start_matches("- ")
            .starts_with("name:")
        {
            continue;
        }
        match line.trim_end().strip_suffix('\\') {
            Some(head) => {
                cur.push_str(head);
                cur.push(' ');
            }
            None => {
                cur.push_str(&line);
                out.push(std::mem::take(&mut cur));
            }
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// `tok` names the crate `krate`: `krate` or `krate@<version>`, quoted or not.
fn names_crate(tok: &str, krate: &str) -> bool {
    let t = tok.trim_matches(QUOTES);
    t == krate || t.starts_with(&format!("{krate}@"))
}

/// The arguments of each `cargo install` on one shell line (`cargo
/// +<toolchain> install` and a path to cargo too), unquoted, each to the
/// shell's next operator.
fn cargo_installs(line: &str) -> Vec<Vec<String>> {
    let unquote = |t: &str| t.trim_matches(QUOTES).to_string();
    let toks: Vec<&str> = line.split_whitespace().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        let is_cargo = toks[i] == "cargo" || toks[i].ends_with("/cargo");
        let mut j = i + 1;
        if is_cargo && toks.get(j).is_some_and(|t| t.starts_with('+')) {
            j += 1;
        }
        if !(is_cargo && toks.get(j) == Some(&"install")) {
            i += 1;
            continue;
        }
        let mut args = Vec::new();
        let mut k = j + 1;
        while k < toks.len() {
            let t = toks[k];
            if matches!(t, "&&" | "||" | ";" | "|") {
                break;
            }
            k += 1;
            if let Some(last) = t.strip_suffix(';') {
                args.push(unquote(last));
                break;
            }
            args.push(unquote(t));
        }
        out.push(args);
        i = k;
    }
    out
}

/// The version each `cargo install` of `krate` on one shell line pins,
/// whatever the order of its flags: `--version X`, `--version=X`, `--vers
/// X`, `--vers=X` or `krate@X`. One without is `"unpinned"`; one from
/// `--git` or `--path` (not crates.io) is `"--git"`/`"--path"`.
fn cargo_install_pins_on(line: &str, krate: &str) -> Vec<String> {
    let mut pins = Vec::new();
    for args in cargo_installs(line) {
        if !args.iter().any(|a| names_crate(a, krate)) {
            continue;
        }
        let (mut pin, mut source) = (None, None);
        for (n, a) in args.iter().enumerate() {
            if let Some(v) = a.strip_prefix(&format!("{krate}@")) {
                pin = Some(v.to_string());
            } else if a == "--version" || a == "--vers" {
                pin = args.get(n + 1).cloned();
            } else if let Some(v) = a
                .strip_prefix("--version=")
                .or_else(|| a.strip_prefix("--vers="))
            {
                pin = Some(v.to_string());
            } else if a == "--git" || a.starts_with("--git=") {
                source = Some("--git");
            } else if a == "--path" || a.starts_with("--path=") {
                source = Some("--path");
            }
        }
        pins.push(match (source, pin) {
            (Some(s), _) => s.to_string(),
            (None, Some(v)) => v,
            (None, None) => "unpinned".to_string(),
        });
    }
    pins
}

/// [`cargo_install_pins_on`] over every shell line of `text`.
fn cargo_install_pins(text: &str, krate: &str) -> Vec<String> {
    shell_lines(text)
        .iter()
        .flat_map(|l| cargo_install_pins_on(l, krate))
        .collect()
}

/// The review of #618 (P3-1): the one-bpf-linker ratchet read only
/// `cargo install bpf-linker --version X`; `cargo install --locked
/// bpf-linker --version 0.11.0` next to it passed. Every spelling cargo
/// takes reads the same.
#[test]
fn a_cargo_install_pin_reads_alike_in_any_flag_order() {
    let pins = |t: &str| cargo_install_pins(t, "bpf-linker");
    // the workflows' own spelling
    assert_eq!(
        pins("cargo install bpf-linker --version 0.10.3 --locked"),
        ["0.10.3"]
    );
    // the review's probe: the flags in another order
    assert_eq!(
        pins("  cargo install --locked bpf-linker --version 0.11.0 --force"),
        ["0.11.0"]
    );
    assert_eq!(
        pins("cargo install --version 0.11.0 --locked bpf-linker"),
        ["0.11.0"]
    );
    assert_eq!(
        pins("cargo install --locked --version=0.11.0 bpf-linker"),
        ["0.11.0"]
    );
    assert_eq!(
        pins("cargo install --vers 0.11.0 --locked bpf-linker"),
        ["0.11.0"]
    );
    assert_eq!(pins("cargo install --locked bpf-linker@0.11.0"), ["0.11.0"]);
    assert_eq!(
        pins("cargo install --locked 'bpf-linker@0.11.0'"),
        ["0.11.0"]
    );
    assert_eq!(
        pins("cargo install --version \"0.11.0\" --locked bpf-linker"),
        ["0.11.0"]
    );
    // a toolchain, a path to cargo, a command after another
    assert_eq!(
        pins("cargo +nightly install --locked bpf-linker --version 0.11.0"),
        ["0.11.0"]
    );
    assert_eq!(
        pins("~/.cargo/bin/cargo install bpf-linker --version 0.11.0 --locked"),
        ["0.11.0"]
    );
    assert_eq!(
        pins("rustup show && cargo install --locked bpf-linker --version 0.11.0; echo ok"),
        ["0.11.0"]
    );
    // one line continued on the next
    assert_eq!(
        pins("cargo install --locked \\\n    bpf-linker \\\n    --version 0.11.0\n"),
        ["0.11.0"]
    );
    // two installs on one line, another crate's version not taken
    assert_eq!(
        pins(
            "cargo install cargo-cyclonedx --version 0.5.7 --locked && cargo install --locked bpf-linker --version 0.11.0"
        ),
        ["0.11.0"]
    );
    // no version, or not from crates.io
    assert_eq!(pins("cargo install --locked bpf-linker"), ["unpinned"]);
    assert_eq!(
        pins("cargo install --git https://github.com/aya-rs/bpf-linker --locked bpf-linker"),
        ["--git"]
    );
    assert_eq!(
        pins("cargo install --path ./bpf-linker-src --locked bpf-linker"),
        ["--path"]
    );
    // not an install of it: another crate, a comment, a step's name, a list
    assert!(pins("cargo install cargo-cyclonedx --version 0.5.7 --locked").is_empty());
    assert!(pins("# cargo install --locked bpf-linker --version 0.11.0").is_empty());
    assert!(pins("echo hi # cargo install bpf-linker --version 0.11.0").is_empty());
    assert!(pins("- name: cargo install bpf-linker --version 0.11.0").is_empty());
    assert!(pins("cargo install --list").is_empty());
    // not a cargo install: the caller refuses the line (it names bpf-linker)
    assert!(pins("cargo binstall bpf-linker --version 0.11.0").is_empty());
    // a `#` inside quotes is not a comment: the install after it is read
    assert_eq!(
        pins("echo \" #\"; cargo install --locked bpf-linker@0.11.0"),
        ["0.11.0"]
    );
}

/// Lab PR 237: a grouped patch/minor bump that moves only the root
/// Cargo.lock leaves fuzz/Cargo.lock behind on the security crates, and
/// `security_crates_are_locked_alike_for_the_fuzzer` goes red (#413). The
/// cargo entry that carries the `rust-minor` group covers both lockfiles.
#[test]
fn dependabot_moves_the_fuzz_lockfile_with_the_root_one() {
    let root = repo_root();
    let dependabot: support::yaml::Value =
        support::yaml::from_str(&read(&root.join(".github/dependabot.yml"))).unwrap();
    let updates = dependabot
        .get("updates")
        .and_then(|u| u.as_sequence())
        .expect(".github/dependabot.yml has an `updates` list");
    let dirs = |e: &support::yaml::Value| -> Vec<String> {
        let mut out: Vec<String> = e
            .get("directories")
            .and_then(|d| d.as_sequence())
            .map(|d| {
                d.iter()
                    .filter_map(|x| x.as_str())
                    .map(|x| x.trim_end_matches('/').to_string())
                    .collect()
            })
            .unwrap_or_default();
        if let Some(d) = str_of(e, "directory") {
            out.push(d.trim_end_matches('/').to_string());
        }
        out
    };
    let grouped: Vec<&support::yaml::Value> = updates
        .iter()
        .filter(|e| {
            str_of(e, "package-ecosystem") == Some("cargo")
                && e.get("groups").and_then(|g| g.get("rust-minor")).is_some()
        })
        .collect();
    assert_eq!(
        grouped.len(),
        1,
        ".github/dependabot.yml needs exactly one cargo entry with the rust-minor group"
    );
    let covered = dirs(grouped[0]);
    for want in ["", "/fuzz"] {
        assert!(
            covered.iter().any(|d| d == want),
            "the rust-minor cargo entry must cover `{}` (directories: [\"/\", \"/fuzz\"]); \
             it covers {covered:?}",
            if want.is_empty() { "/" } else { want }
        );
    }
    // The fuzz lockfile is not left to a second, ungrouped entry that
    // would bump it on its own schedule.
    let fuzz_elsewhere = updates.iter().any(|e| {
        str_of(e, "package-ecosystem") == Some("cargo")
            && !std::ptr::eq(e, grouped[0])
            && dirs(e).iter().any(|d| d == "/fuzz")
    });
    assert!(
        !fuzz_elsewhere,
        "/fuzz belongs to the rust-minor cargo entry only"
    );
}

/// SUP-015: the declared floor is not below what the locked dependencies
/// declare for the platform the product ships on. cargo metadata runs
/// offline: a workspace build has already downloaded those crates (CI's
/// test job builds before it tests).
#[test]
fn rust_version_covers_every_locked_dependency() {
    let root = repo_root();
    let (declared, floor) = declared_rust_version();
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let out = std::process::Command::new(cargo)
        .current_dir(&root)
        .args([
            "metadata",
            "--locked",
            "--offline",
            "--format-version",
            "1",
            "--filter-platform",
            "x86_64-unknown-linux-gnu",
        ])
        .output()
        .expect("cargo metadata runs");
    assert!(
        out.status.success(),
        "cargo metadata --locked --offline failed (build the workspace once, or \
         `cargo fetch --locked`):\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: serde_json::Value = serde_json::from_slice(&out.stdout).expect("metadata JSON");
    let members: Vec<&str> = meta["workspace_members"]
        .as_array()
        .expect("workspace_members")
        .iter()
        .filter_map(|m| m.as_str())
        .collect();
    let mut checked = 0;
    let mut above = Vec::new();
    for pkg in meta["packages"].as_array().expect("packages") {
        if members.contains(&pkg["id"].as_str().unwrap_or("")) {
            continue;
        }
        let Some(rv) = pkg["rust_version"].as_str() else {
            continue;
        };
        checked += 1;
        let needs =
            rust_version(rv).unwrap_or_else(|| panic!("{}: rust_version {rv}", pkg["name"]));
        if needs > floor {
            above.push(format!(
                "{} {} needs {rv}",
                pkg["name"].as_str().unwrap_or("?"),
                pkg["version"].as_str().unwrap_or("?")
            ));
        }
    }
    assert!(
        checked > 50,
        "only {checked} locked packages declare a rust-version"
    );
    assert!(
        above.is_empty(),
        "Cargo.toml rust-version {declared} is below what the locked dependencies need \
         (raise it in the same PR):\n{}",
        above.join("\n")
    );
}

/// SUP-012: the prune step must not pass when it pruned nothing because
/// cargo metadata failed: the restored workspace artifacts would stay and
/// could be taken as fresh. Runs the script with a stub `cargo` first on
/// PATH. Lot 397: the target dir holds both of Cargo's build-dir layouts
/// (the workspace's 1.100 and the nightly of agent-ebpf/ and fuzz/), and the
/// workspace crates go from each while the dependencies stay.
#[cfg(unix)]
#[test]
fn prune_script_fails_closed() {
    use std::os::unix::fs::PermissionsExt;
    let script = repo_root().join(".github/scripts/prune-workspace-cache.sh");
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join("prune-workspace-cache");
    let _ = fs::remove_dir_all(&base);
    let run = |case: &str, stub: &str| {
        let dir = base.join(case);
        let bin = dir.join("bin");
        let target = dir.join("target");
        for d in OLD_LAYOUT
            .iter()
            .chain(&NEW_LAYOUT)
            .flat_map(|(w, d)| [w, d])
        {
            fs::create_dir_all(target.join(d)).unwrap();
        }
        fs::create_dir_all(&bin).unwrap();
        let cargo = bin.join("cargo");
        fs::write(&cargo, format!("#!/bin/sh\n{stub}\n")).unwrap();
        fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755)).unwrap();
        let path = format!(
            "{}:{}",
            bin.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let out = std::process::Command::new("bash")
            .arg(&script)
            .arg(&target)
            .env("PATH", path)
            .output()
            .expect("bash runs");
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        (out.status.success(), stdout, target)
    };

    for (case, stub) in [
        ("metadata-fails", "exit 1"),
        ("no-packages", r#"echo '{"packages":[]}'"#),
        ("not-json", "echo 'error: something else'"),
        ("empty-name", r#"echo '{"packages":[{"name":""}]}'"#),
    ] {
        let (ok, stdout, target) = run(case, stub);
        assert!(!ok, "{case}: the prune step must fail; stdout: {stdout}");
        assert!(!stdout.contains("pruned"), "{case}: {stdout}");
        assert!(
            target
                .join("debug/.fingerprint/northnarrow-agent-0123")
                .exists()
        );
    }

    let (ok, stdout, target) = run(
        "two-crates",
        r#"echo '{"packages":[{"name":"northnarrow-agent"},{"name":"xtask"}]}'"#,
    );
    assert!(ok, "two crates: {stdout}");
    assert!(
        stdout.contains("pruned workspace artifacts (2 crates)"),
        "{stdout}"
    );
    assert!(
        !target
            .join("debug/.fingerprint/northnarrow-agent-0123")
            .exists(),
        "the workspace crate's fingerprint is removed"
    );
    assert!(
        target.join("debug/.fingerprint/serde-4567").exists(),
        "a dependency's fingerprint is kept"
    );
    for (workspace, dependency) in OLD_LAYOUT.iter().chain(&NEW_LAYOUT) {
        assert!(
            !target.join(workspace).exists(),
            "a workspace crate's {workspace} is removed"
        );
        assert!(
            target.join(dependency).exists(),
            "a dependency's {dependency} is kept"
        );
    }
}

/// (a workspace crate's artifact, a dependency's) in Cargo's build-dir
/// layout up to 1.99, as the nightly of agent-ebpf/ and fuzz/ still lays it.
const OLD_LAYOUT: [(&str, &str); 4] = [
    (
        "debug/.fingerprint/northnarrow-agent-0123",
        "debug/.fingerprint/serde-4567",
    ),
    (
        "debug/deps/libnorthnarrow_agent-0123.rlib",
        "debug/deps/libserde-4567.rlib",
    ),
    (
        "debug/build/northnarrow-agent-89ab",
        "debug/build/serde-cdef",
    ),
    (
        "debug/incremental/xtask-1abc",
        "debug/incremental/serde-2def",
    ),
];

/// The same in Cargo 1.100's layout (the workspace's `rust-toolchain.toml`,
/// lot 397): `<profile>/build/<package>/<hash>/{fingerprint,out}`, also under
/// a target triple.
const NEW_LAYOUT: [(&str, &str); 3] = [
    (
        "debug/build/northnarrow-agent/0123456789abcdef/fingerprint",
        "debug/build/serde/456789abcdef0123/fingerprint",
    ),
    (
        "release/build/xtask/89abcdef01234567/out",
        "release/build/serde_json/cdef0123456789ab/out",
    ),
    (
        "x86_64-unknown-linux-gnu/release/build/northnarrow-agent/0123456789abcdef/out",
        "x86_64-unknown-linux-gnu/release/build/serde/456789abcdef0123/out",
    ),
];

/// SUP-006 (residual of Wave 2): an advisory published against an
/// unchanged main must not wait for the next push. ci.yml runs on a
/// schedule, and its audit job is not skipped there.
#[test]
fn advisories_are_checked_on_a_schedule() {
    let ci = workflow_yaml(&repo_root().join(".github/workflows/ci.yml"));
    let on = ci.get("on").expect("ci.yml has `on:`");
    let cron = on
        .get("schedule")
        .and_then(|s| s.as_sequence())
        .is_some_and(|s| s.iter().any(|e| str_of(e, "cron").is_some()));
    assert!(cron, "ci.yml needs `on: schedule: - cron: …`");
    let audit = jobs(&ci)
        .into_iter()
        .find(|(_, body)| {
            steps(body)
                .iter()
                .any(|s| str_of(s, "run").is_some_and(|r| r.contains("cargo audit --file")))
        })
        .expect("ci.yml has the cargo audit job");
    assert!(
        !str_of(&audit.1, "if").is_some_and(|c| c.contains("schedule")),
        "the audit job ({}) must run on the schedule",
        audit.0
    );
}

// ---------------------------------------------------------------------------
// SUP-007 to SUP-011: the RustSEC advisory policy (.cargo/audit.toml).

/// The lockfiles the audit job checks (SUP-006).
const LOCKFILES: [&str; 3] = ["Cargo.lock", "fuzz/Cargo.lock", "agent-ebpf/Cargo.lock"];

/// The longest an advisory exception may be accepted before it is re-checked
/// and recorded again (about six months).
const MAX_EXCEPTION_DAYS: i64 = 184;

/// `name -> locked versions` of a Cargo.lock.
fn locked_versions(lock: &Path) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut out: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    let mut name: Option<String> = None;
    for line in read(lock).lines() {
        if line.trim() == "[[package]]" {
            name = None;
        } else if let Some(v) = line.strip_prefix("name = ") {
            name = Some(v.trim().trim_matches('"').to_string());
        } else if let Some(v) = line.strip_prefix("version = ") {
            if let Some(n) = name.take() {
                out.entry(n)
                    .or_default()
                    .push(v.trim().trim_matches('"').to_string());
            }
        }
    }
    for versions in out.values_mut() {
        versions.sort();
    }
    out
}

/// One `ignore` entry of .cargo/audit.toml with its comment block.
#[derive(Debug)]
struct AdvisoryException {
    id: String,
    /// The block's first comment, continuation lines joined.
    header: String,
    /// `Field: value` comments, continuation lines (`#   …`) joined.
    fields: Vec<(String, String)>,
    /// Comments that are neither the header, a known field nor a continuation.
    stray: Vec<String>,
}

const EXCEPTION_FIELDS: [&str; 5] = ["Why", "Owner", "Re-check", "Recorded", "Expires"];

fn advisory_exceptions(text: &str) -> Vec<AdvisoryException> {
    let mut out = Vec::new();
    let mut inside = false;
    let mut header: Option<String> = None;
    let mut fields: Vec<(String, String)> = Vec::new();
    let mut stray = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if !inside {
            inside = t.starts_with("ignore") && t.ends_with('[');
            continue;
        }
        if t.starts_with(']') {
            break;
        }
        if let Some(c) = t.strip_prefix('#') {
            if c.starts_with("   ") {
                let more = c.trim();
                match (fields.last_mut(), header.as_mut()) {
                    (Some((_, v)), _) => {
                        v.push(' ');
                        v.push_str(more);
                    }
                    (None, Some(h)) => {
                        h.push(' ');
                        h.push_str(more);
                    }
                    (None, None) => stray.push(c.to_string()),
                }
                continue;
            }
            let c = c.trim();
            if header.is_none() {
                header = Some(c.to_string());
            } else if let Some((k, v)) = c
                .split_once(':')
                .filter(|(k, _)| EXCEPTION_FIELDS.contains(k))
            {
                fields.push((k.to_string(), v.trim().to_string()));
            } else {
                stray.push(c.to_string());
            }
            continue;
        }
        if t.is_empty() {
            continue;
        }
        out.push(AdvisoryException {
            id: t.trim_end_matches(',').trim_matches('"').to_string(),
            header: header.take().unwrap_or_default(),
            fields: std::mem::take(&mut fields),
            stray: std::mem::take(&mut stray),
        });
    }
    out
}

fn is_rustsec_id(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("RUSTSEC-") else {
        return false;
    };
    let parts: Vec<&str> = rest.split('-').collect();
    parts.len() == 2
        && parts[0].len() == 4
        && parts[1].len() == 4
        && parts.iter().all(|p| p.bytes().all(|b| b.is_ascii_digit()))
}

/// SUP-007, SUP-008, SUP-009, SUP-011: an informational advisory that
/// cannot be fixed is accepted only as a recorded exception — the ID with
/// the crate and version it was reasoned about, why it is not reachable or
/// has no fix, who re-checks it, when, and until which date. The crate must
/// still be locked at that version: the reasoning was about that version
/// and its dependents' code, so a bump that moves it (a dependent taking
/// another version) reopens the entry here instead of leaving an ignore that
/// accepts the advisory for whatever is locked next.
#[test]
fn every_advisory_exception_is_reasoned_and_dated() {
    let root = repo_root();
    let path = root.join(".cargo/audit.toml");
    assert!(
        path.is_file(),
        "{}: the advisory policy file is missing (SUP-007)",
        rel(&path)
    );
    let text = read(&path);
    let entries = advisory_exceptions(&text);
    let quoted = text
        .lines()
        .filter(|l| !l.trim_start().starts_with('#') && l.contains("\"RUSTSEC-"))
        .count();
    assert_eq!(
        entries.len(),
        quoted,
        "every RUSTSEC id in .cargo/audit.toml is one line of `ignore = [`, after its \
         comment block: {entries:#?}"
    );
    let locks: Vec<(&str, _)> = LOCKFILES
        .iter()
        .map(|l| (*l, locked_versions(&root.join(l))))
        .collect();

    let mut bad = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for e in &entries {
        let id = &e.id;
        if !is_rustsec_id(id) {
            bad.push(format!("`{id}`: not a RUSTSEC-YYYY-NNNN id"));
            continue;
        }
        if !seen.insert(id.clone()) {
            bad.push(format!("{id}: listed twice"));
        }
        for s in &e.stray {
            bad.push(format!("{id}: unexpected comment line `{s}`"));
        }
        // `<ID>: <crate> <version>, <kind>.`
        let named = e
            .header
            .strip_prefix(id.as_str())
            .and_then(|h| h.strip_prefix(": "))
            .map(|h| h.split_whitespace().take(3).collect::<Vec<_>>());
        match named.as_deref() {
            Some([krate, version, kind])
                if version.ends_with(',')
                    && ["unsound.", "unmaintained.", "notice.", "vulnerability."]
                        .contains(kind) =>
            {
                let version = version.trim_end_matches(',');
                let locked_in: Vec<&str> = locks
                    .iter()
                    .filter(|(_, v)| {
                        v.get(*krate)
                            .is_some_and(|vs| vs.iter().any(|x| x == version))
                    })
                    .map(|(l, _)| *l)
                    .collect();
                if locked_in.is_empty() {
                    bad.push(format!(
                        "{id}: {krate} {version} is in no lockfile any more: drop the \
                         exception, or re-check the advisory against what is locked now"
                    ));
                }
            }
            _ => bad.push(format!(
                "{id}: the block must start `# {id}: <crate> <version>, <unsound|unmaintained|\
                 notice|vulnerability>.`, not `# {}`",
                e.header
            )),
        }
        let field = |name: &str| -> Option<&str> {
            let all: Vec<&str> = e
                .fields
                .iter()
                .filter(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
                .collect();
            match all[..] {
                [one] if !one.is_empty() => Some(one),
                _ => None,
            }
        };
        for name in EXCEPTION_FIELDS {
            if field(name).is_none() {
                bad.push(format!("{id}: needs exactly one non-empty `{name}:` line"));
            }
        }
        if field("Why").is_some_and(|w| w.len() < 60) {
            bad.push(format!("{id}: `Why:` is too short to be a reason"));
        }
        let date =
            |name: &str| field(name).and_then(|d| jiff::civil::Date::strptime("%Y-%m-%d", d).ok());
        match (date("Recorded"), date("Expires")) {
            (Some(from), Some(until)) => {
                let days = until.duration_since(from).as_hours() / 24;
                if !(0..=MAX_EXCEPTION_DAYS).contains(&days) {
                    bad.push(format!(
                        "{id}: accepted for {days} days ({from} to {until}); at most \
                         {MAX_EXCEPTION_DAYS}: re-check it and record it again"
                    ));
                }
            }
            _ => bad.push(format!(
                "{id}: `Recorded:` and `Expires:` must be dates (YYYY-MM-DD)"
            )),
        }
    }
    assert!(
        bad.is_empty(),
        "advisory exceptions in .cargo/audit.toml (format at the top of that file):\n{}",
        bad.join("\n")
    );
}

/// Lot M3 (OpenSSF Scorecard, Vulnerabilities): unsafe-libyaml, unsafe
/// Rust machine-translated from libyaml's C and archived upstream
/// (RUSTSEC-2024-0449), was in Cargo.lock under serde_yaml_ng, the xtask
/// tests' YAML reader, with an exception in .cargo/audit.toml; they read
/// YAML with serde-saphyr, in safe Rust (`support/yaml.rs`), now. No
/// lockfile holds it again, nor the readers built on it or on its forks
/// (libyml, RUSTSEC-2025-0067; unsafe-libyaml-norway).
#[test]
fn no_lockfile_holds_a_yaml_reader_translated_from_c() {
    const TRANSLATED: [&str; 7] = [
        "unsafe-libyaml",
        "unsafe-libyaml-norway",
        "libyml",
        "serde_yaml",
        "serde_yaml_ng",
        "serde_yml",
        "serde_norway",
    ];
    let found = |lock: &str, locked: &std::collections::BTreeMap<String, Vec<String>>| {
        TRANSLATED
            .iter()
            .filter_map(|name| Some(format!("{lock}: {name} {}", locked.get(*name)?.join(", "))))
            .collect::<Vec<_>>()
    };
    // the check, on main's Cargo.lock before lot M3
    let before: std::collections::BTreeMap<String, Vec<String>> = [
        ("serde_yaml_ng", "0.10.0"),
        ("unsafe-libyaml", "0.2.11"),
        ("serde", "1.0.229"),
    ]
    .map(|(n, v)| (n.to_string(), vec![v.to_string()]))
    .into();
    assert_eq!(
        found("Cargo.lock", &before),
        [
            "Cargo.lock: unsafe-libyaml 0.2.11",
            "Cargo.lock: serde_yaml_ng 0.10.0"
        ]
    );
    let root = repo_root();
    let mut bad = Vec::new();
    for lock in LOCKFILES {
        let locked = locked_versions(&root.join(lock));
        assert!(locked.len() > 20, "{lock}: {} packages", locked.len());
        bad.extend(found(lock, &locked));
    }
    assert!(
        bad.is_empty(),
        "a YAML reader in unsafe Rust translated from libyaml's C is locked again \
         (read YAML with xtask/tests/support/yaml.rs):\n{}",
        bad.join("\n")
    );
}

/// SUP-007: `unsound` and `unmaintained` advisories fail the audit job;
/// they were warnings nobody had to read. Every `cargo audit` in the
/// workflows denies them on its command line (it holds even if the config is
/// not read), ignores nothing there (an exception lives in
/// .cargo/audit.toml with its reason) and narrows nothing (a stale or
/// another database, a target filter); the config denies them too, so a
/// local run gives the CI verdict, and holds nothing else that could narrow
/// what is reported (a severity threshold, for one). The audit job checks
/// the exceptions' expiry before it audits.
#[test]
fn the_advisory_gate_denies_unsound_and_unmaintained() {
    let root = repo_root();
    let mut calls = 0;
    let mut bad = Vec::new();
    for file in workflow_files() {
        let wf = workflow_yaml(&file);
        for (job, body) in jobs(&wf) {
            for step in steps(&body) {
                for call in cargo_calls(str_of(&step, "run").unwrap_or("")) {
                    if call.sub != "audit" {
                        continue;
                    }
                    calls += 1;
                    let at = format!("{}: job {job}: {}", rel(&file), call.line);
                    let denies = |kind: &str| {
                        call.args
                            .windows(2)
                            .any(|w| (w[0] == "--deny" || w[0] == "-D") && w[1] == kind)
                            || call.args.iter().any(|a| *a == format!("--deny={kind}"))
                    };
                    for kind in ["unsound", "unmaintained"] {
                        if !denies(kind) {
                            bad.push(format!("{at}: no `--deny {kind}`"));
                        }
                    }
                    if call.args.iter().any(|a| a.starts_with("--ignore")) {
                        bad.push(format!(
                            "{at}: `--ignore` on the command line (record the exception in \
                             .cargo/audit.toml, with its reason)"
                        ));
                    }
                    // What would audit less: an old or another database, or
                    // one platform's advisories only.
                    const NARROWING: [&str; 7] = [
                        "--stale",
                        "--no-fetch",
                        "-n",
                        "--db",
                        "--url",
                        "--target-arch",
                        "--target-os",
                    ];
                    for a in &call.args {
                        let flag = a.split('=').next().unwrap_or("");
                        if NARROWING.contains(&flag) {
                            bad.push(format!("{at}: `{a}` narrows the audit"));
                        }
                    }
                }
            }
        }
    }
    assert!(calls > 0, "no `cargo audit` in the workflows");

    let ci = workflow_yaml(&root.join(".github/workflows/ci.yml"));
    let (job, body) = jobs(&ci)
        .into_iter()
        .find(|(_, body)| {
            steps(body)
                .iter()
                .any(|s| str_of(s, "run").is_some_and(|r| r.contains("cargo audit --file")))
        })
        .expect("ci.yml has the cargo audit job");
    let runs: Vec<String> = steps(&body)
        .iter()
        .map(|s| str_of(s, "run").unwrap_or("").to_string())
        .collect();
    let expiry = runs
        .iter()
        .position(|r| r.contains(".github/scripts/check-audit-exceptions.sh"));
    let audit = runs.iter().position(|r| r.contains("cargo audit --file"));
    if !matches!((expiry, audit), (Some(e), Some(a)) if e < a) {
        bad.push(format!(
            "ci.yml: job {job} must run .github/scripts/check-audit-exceptions.sh before \
             `cargo audit`"
        ));
    }

    // Missing, it denies nothing: reported below rather than a panic here.
    let config = fs::read_to_string(root.join(".cargo/audit.toml")).unwrap_or_default();
    let deny = toml_string(&config, "output", "deny").unwrap_or_default();
    for kind in ["unsound", "unmaintained"] {
        if !deny.contains(&format!("\"{kind}\"")) {
            bad.push(format!(".cargo/audit.toml: [output] deny lacks \"{kind}\""));
        }
    }
    const ALLOWED: [(&str, &str); 3] = [
        ("advisories", "ignore"),
        ("output", "deny"),
        ("output", "quiet"),
    ];
    let mut section = String::new();
    let mut in_array = false;
    for line in config.lines() {
        let l = line.split('#').next().unwrap_or("").trim();
        if in_array {
            in_array = !l.starts_with(']');
            continue;
        }
        if l.is_empty() {
            continue;
        }
        if l.starts_with('[') {
            section = l.trim_matches(|c| c == '[' || c == ']').trim().to_string();
            continue;
        }
        let key = l.split('=').next().unwrap_or("").trim();
        if !ALLOWED.contains(&(section.as_str(), key)) {
            bad.push(format!(
                ".cargo/audit.toml: [{section}] {key}: not part of the policy (it can narrow \
                 what the gate reports; add it to this test with its reason)"
            ));
        }
        in_array = l.ends_with('[');
    }
    if toml_string(&config, "output", "quiet").as_deref() != Some("false") {
        bad.push(".cargo/audit.toml: [output] quiet must be false".to_string());
    }
    assert!(
        bad.is_empty(),
        "the RustSEC gate must deny unsound and unmaintained advisories:\n{}",
        bad.join("\n")
    );
}

/// SUP-007: cargo-audit has no notion of an exception's end, so the audit
/// job runs .github/scripts/check-audit-exceptions.sh, which fails the day
/// after an `Expires:` date (the daily schedule included) and on an entry
/// without a valid one. Runs the script under bash with a fixed date.
#[cfg(unix)]
#[test]
fn advisory_exceptions_expire_in_ci() {
    let root = repo_root();
    let script = root.join(".github/scripts/check-audit-exceptions.sh");
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join("check-audit-exceptions");
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    let run = |config: &Path, today: &str| {
        let out = std::process::Command::new("bash")
            .arg(&script)
            .arg(config)
            .arg(today)
            .output()
            .expect("bash runs");
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), text)
    };
    let fixture = |name: &str, body: &str| {
        let p = base.join(name);
        fs::write(&p, body).unwrap();
        p
    };

    // The committed policy: accepted on the day the last entry was recorded
    // and on the day the first expires; refused the day after.
    let real = root.join(".cargo/audit.toml");
    let entries = advisory_exceptions(&fs::read_to_string(&real).unwrap_or_default());
    let dates = |name: &str| -> Vec<jiff::civil::Date> {
        entries
            .iter()
            .filter_map(|e| e.fields.iter().find(|(k, _)| k == name))
            .filter_map(|(_, v)| jiff::civil::Date::strptime("%Y-%m-%d", v).ok())
            .collect()
    };
    if let (Some(first), Some(last)) = (
        dates("Recorded").into_iter().max(),
        dates("Expires").into_iter().min(),
    ) {
        for day in [first, last].into_iter().filter(|_| first <= last) {
            let (ok, text) = run(&real, &day.to_string());
            assert!(ok, "the committed exceptions on {day}: {text}");
            assert!(
                text.contains(&format!("{} exception(s)", entries.len())),
                "{text}"
            );
        }
        let after = last.tomorrow().unwrap();
        let (ok, text) = run(&real, &after.to_string());
        assert!(!ok, "{after} is after an expiry: {text}");
        assert!(text.contains(&format!("expired on {last}")), "{text}");
    }

    let entry = |expires: &str| {
        format!(
            "[advisories]\nignore = [\n    # RUSTSEC-2024-0436: paste 1.0.15, unmaintained.\n    \
             # Why: fixture.\n{expires}    \"RUSTSEC-2024-0436\",\n]\n"
        )
    };
    let ok_body = entry("    # Expires: 2027-01-20\n");
    for (case, body, today, want_ok, needle) in [
        (
            "valid",
            ok_body.as_str(),
            "2026-12-31",
            true,
            "1 exception(s)",
        ),
        (
            "last-day",
            ok_body.as_str(),
            "2027-01-20",
            true,
            "1 exception(s)",
        ),
        (
            "expired",
            ok_body.as_str(),
            "2027-01-21",
            false,
            "expired on 2027-01-20",
        ),
        ("no-expiry", &entry(""), "2026-12-31", false, "no Expires:"),
        (
            "bad-date",
            &entry("    # Expires: 20 January 2027\n"),
            "2026-12-31",
            false,
            "is not YYYY-MM-DD",
        ),
        (
            "inline",
            "[advisories]\nignore = [\"RUSTSEC-2024-0436\"]\n",
            "2026-12-31",
            false,
            "one exception per line",
        ),
        (
            "not-closed",
            "[advisories]\nignore = [\n    # Expires: 2027-01-20\n    \"RUSTSEC-2024-0436\",\n",
            "2026-12-31",
            false,
            "is not closed",
        ),
        (
            "two-ids",
            "[advisories]\nignore = [\n    # Expires: 2027-01-20\n    \"RUSTSEC-2024-0436\", \"RUSTSEC-2026-0002\",\n]\n",
            "2026-12-31",
            false,
            "not one quoted RUSTSEC id",
        ),
        (
            "empty",
            "[advisories]\nignore = []\n",
            "2026-12-31",
            true,
            "0 exception(s)",
        ),
        (
            "none",
            "[output]\nquiet = false\n",
            "2026-12-31",
            true,
            "0 exception(s)",
        ),
    ] {
        let (ok, text) = run(&fixture(case, body), today);
        assert_eq!(ok, want_ok, "{case}: {text}");
        assert!(text.contains(needle), "{case}: `{needle}` not in: {text}");
    }
    let (ok, text) = run(&base.join("missing.toml"), "2026-12-31");
    assert!(!ok && text.contains("not found"), "missing file: {text}");
}

/// SUP-008: the lru exception rested partly on the release profile aborting
/// on a panic (no unwinding, so no `catch_unwind` could observe the
/// half-done `pop()`); lru left with the LLM advisor in Wave 4 (lab PR 214),
/// and the property stays: the shipped profile, and every profile built
/// from it, keeps `panic = "abort"`.
#[test]
fn release_profile_aborts_on_panic() {
    let text = read(&repo_root().join("Cargo.toml"));
    let mut profiles: Vec<String> = Vec::new();
    for line in text.lines() {
        let l = line.split('#').next().unwrap_or("").trim();
        if let Some(name) = l
            .strip_prefix("[profile.")
            .and_then(|r| r.strip_suffix(']'))
        {
            if !name.contains('.') {
                profiles.push(name.to_string());
            }
        }
    }
    assert!(
        profiles.iter().any(|p| p == "release"),
        "Cargo.toml has no [profile.release]"
    );
    let mut bad = Vec::new();
    for p in &profiles {
        // The inheritance chain from `p` (cargo's built-in profiles end it).
        let mut chain = vec![p.clone()];
        while let Some(parent) = toml_string(
            &text,
            &format!("profile.{}", chain[chain.len() - 1]),
            "inherits",
        ) {
            assert!(
                chain.len() < 8,
                "profile inheritance loop from {p}: {chain:?}"
            );
            chain.push(parent);
        }
        if !chain.iter().any(|c| c == "release") {
            continue;
        }
        let panic = chain
            .iter()
            .find_map(|c| toml_string(&text, &format!("profile.{c}"), "panic"));
        if panic.as_deref() != Some("abort") {
            bad.push(format!(
                "[profile.{p}] (from {}): panic = {}",
                chain.join(" <- "),
                panic.as_deref().unwrap_or("(default: unwind)")
            ));
        }
    }
    assert!(
        bad.is_empty(),
        "the release profile and the profiles that inherit it must keep panic = \"abort\":\n{}",
        bad.join("\n")
    );
}

/// The fuzz harness builds the agent from its own lockfile. A crate locked
/// at another version there is fuzzed as code the agent does not ship, and a
/// security bump applied to one lockfile only leaves the other behind
/// (memmap2: 0.9.11 in fuzz/Cargo.lock, 0.9.10 in Cargo.lock until
/// SUP-010; tokio 1.53.3 broke the fuzz build while fuzz/Cargo.lock kept
/// 1.53.2, #365). For the crates that decide a security property, and for
/// every crate an advisory exception names, both lockfiles lock the same
/// versions. The rest may drift (the fuzz lock is resolved on its own).
#[test]
fn security_crates_are_locked_alike_for_the_fuzzer() {
    const SECURITY_CRATES: &[&str] = &[
        // the async runtime the sensors and the admin socket run on
        "tokio",
        // the wire and the JSON the fuzz targets decode
        "serde",
        "serde_json",
        "postcard",
        "ciborium",
        // signatures, keys and the chains' hashes
        "ed25519-dalek",
        "curve25519-dalek",
        "sha2",
        "hkdf",
        "hmac",
        "aes-gcm",
        "zeroize",
        "subtle",
        // the OS CSPRNG behind every key and nonce (`os_rng`, lab PR 234),
        // and JA3's MD5
        "rand",
        "rand_core",
        "getrandom",
        "md-5",
        // the kernel interface and the BTF/ELF parsing (procfs and
        // procfs-core left the agent's graph with lot 398: no code of the
        // agent named them, and nn-linux's tests alone read procfs, a
        // dev-dependency the fuzz lockfile does not lock)
        "libc",
        "nix",
        // lot 1.8: nn-admin's safe system calls — the effective uid of the
        // private key's owner check (AUT-002) and `heartbeat watch`'s poll —
        // and its raw Linux backend's numbers and layouts (RUSTSEC-2026-0486
        // was rustix's, in both lockfiles: lot 305)
        "rustix",
        "linux-raw-sys",
        "aya",
        "aya-obj",
        "object",
        // (tantivy, candle-core, tokenizers, safetensors and memmap2, the LLM
        // advisor's model and knowledge base and what they mapped from disk,
        // left the graph with the advisor in Wave 4, lab PR 214; so did lru
        // and paste, the crates of its advisory exceptions.)
        // The crates of the recorded exceptions are taken from audit.toml.
    ];
    let root = repo_root();
    let main = locked_versions(&root.join("Cargo.lock"));
    let fuzz = locked_versions(&root.join("fuzz/Cargo.lock"));
    let mut names: Vec<String> = SECURITY_CRATES.iter().map(|s| s.to_string()).collect();
    let config = fs::read_to_string(root.join(".cargo/audit.toml")).unwrap_or_default();
    for e in advisory_exceptions(&config) {
        let krate = e
            .header
            .split(": ")
            .nth(1)
            .and_then(|h| h.split_whitespace().next());
        if let Some(k) = krate {
            if main.contains_key(k) && fuzz.contains_key(k) && !names.iter().any(|n| n == k) {
                names.push(k.to_string());
            }
        }
    }
    let mut bad = Vec::new();
    for name in &names {
        match (main.get(name), fuzz.get(name)) {
            (Some(a), Some(b)) if a == b => {}
            (Some(a), Some(b)) => bad.push(format!(
                "{name}: Cargo.lock {} / fuzz/Cargo.lock {}",
                a.join(", "),
                b.join(", ")
            )),
            (a, b) => bad.push(format!(
                "{name}: not in both lockfiles (Cargo.lock {a:?}, fuzz/Cargo.lock {b:?}); \
                 if it left the graph, drop it from this list"
            )),
        }
    }
    assert!(
        bad.is_empty(),
        "security crates locked differently for the fuzz harness (apply the bump to both \
         lockfiles: `cargo update -p <crate> --precise <v>` at the root and in fuzz/):\n{}",
        bad.join("\n")
    );
}

// ---------------------------------------------------------------------------
// SUP-018 and SUP-023: fuzzing and the proofs as pull-request gates.

/// The `[[bin]]` targets of fuzz/Cargo.toml: name and source path.
fn fuzz_targets() -> Vec<(String, String)> {
    let text = read(&repo_root().join("fuzz/Cargo.toml"));
    let mut out = Vec::new();
    for block in text.split("[[bin]]").skip(1) {
        let field = |key: &str| {
            block
                .lines()
                .take_while(|l| !l.trim_start().starts_with('['))
                .find_map(|l| {
                    let (k, v) = l.split_once('=')?;
                    (k.trim() == key).then(|| v.trim().trim_matches('"').to_string())
                })
                .unwrap_or_else(|| panic!("fuzz/Cargo.toml: a [[bin]] without `{key}`"))
        };
        out.push((field("name"), field("path")));
    }
    // 11 since Wave 4: `ade_verdict` and `ade_preparse` left with the LLM
    // advisor (lab PR 214).
    assert!(out.len() >= 11, "fuzz/Cargo.toml: {} targets", out.len());
    out
}

/// The names of the directories under `dir`.
fn subdirs(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .map(|e| e.expect("readable directory entry").path())
        .filter(|p| p.is_dir())
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    out.sort();
    out
}

/// SUP-018 (NN-AUD-402), WDG-R06 (NN-AUD-372): the CI smoke started every
/// target from an empty directory, and the inputs that reach the targets'
/// assertions (a CIDR that validates, a template that renders, a marker
/// that verifies) are rarely found in 20 s. Every target has committed
/// seeds; every directory of seeds and regressions is a target's; neither
/// is ignored by git; the fuzz job replays both with `-runs=0` and smokes
/// from the corpus (written) and the seeds (only read); the README names
/// every target. That the seeds reach the assertions is
/// `fuzz_api::tests` in the agent.
#[test]
fn every_fuzz_target_has_seeds_and_the_ci_replays_them() {
    let root = repo_root();
    let targets = fuzz_targets();
    let names: Vec<&str> = targets.iter().map(|(n, _)| n.as_str()).collect();
    let mut bad = Vec::new();
    for (name, path) in &targets {
        if !root.join("fuzz").join(path).is_file() {
            bad.push(format!("{name}: no source at fuzz/{path}"));
        }
        let seeds = root.join("fuzz/seeds").join(name);
        let files = fs::read_dir(&seeds)
            .map(|d| {
                d.filter(|e| e.as_ref().is_ok_and(|e| e.path().is_file()))
                    .count()
            })
            .unwrap_or(0);
        if files == 0 {
            bad.push(format!("{name}: no seed under fuzz/seeds/{name}/"));
        }
    }
    for kind in ["seeds", "regressions"] {
        for dir in subdirs(&root.join("fuzz").join(kind)) {
            if !names.contains(&dir.as_str()) {
                bad.push(format!("fuzz/{kind}/{dir}/: no such target"));
            }
        }
    }
    let ignore = read(&root.join("fuzz/.gitignore"));
    for line in ignore.lines().map(str::trim) {
        if ["seeds", "regressions", "*", "/*"]
            .iter()
            .any(|p| line.trim_end_matches('/') == *p)
        {
            bad.push(format!(
                "fuzz/.gitignore ignores the committed inputs: `{line}`"
            ));
        }
    }
    let readme = read(&root.join("fuzz/README.md"));
    for name in &names {
        if !readme.contains(&format!("`{name}`")) {
            bad.push(format!("fuzz/README.md does not name `{name}`"));
        }
    }

    let ci = workflow_yaml(&root.join(".github/workflows/ci.yml"));
    let fuzz = jobs(&ci)
        .into_iter()
        .find(|(name, _)| name == "fuzz")
        .expect("ci.yml has the fuzz job")
        .1;
    let job_steps = steps(&fuzz);
    let script = job_steps
        .iter()
        .filter_map(|s| str_of(s, "run"))
        .find(|r| r.contains("fuzz build"))
        .expect("the fuzz job builds the targets");
    let lines = script_lines(script);
    let replay = lines.iter().find(|l| l.contains("-runs=0"));
    match replay {
        Some(l) if l.contains("${inputs[@]}") => {}
        _ => bad.push("ci.yml fuzz: no `-runs=0` replay of the committed inputs".into()),
    }
    for want in [
        r#"inputs=("fuzz/seeds/$t")"#,
        r#"inputs+=("fuzz/regressions/$t")"#,
    ] {
        if !script.contains(want) {
            bad.push(format!("ci.yml fuzz: the replay misses `{want}`"));
        }
    }
    let smoke = lines.iter().find(|l| l.contains("-max_total_time="));
    match smoke {
        Some(l) if l.contains(r#""fuzz/corpus/$t" "fuzz/seeds/$t""#) => {}
        _ => bad.push(
            "ci.yml fuzz: the smoke must run from \"fuzz/corpus/$t\" \"fuzz/seeds/$t\" \
             (the corpus first: libFuzzer writes only into the first directory)"
                .into(),
        ),
    }
    if !lines
        .iter()
        .any(|l| l.contains("-timeout=") && l.contains("-runs=0"))
    {
        bad.push("ci.yml fuzz: the replay needs a -timeout (a hang is a failure)".into());
    }
    let corpus_cached = job_steps.iter().any(|s| {
        str_of(s, "uses").is_some_and(|u| u.starts_with("actions/cache@"))
            && s.get("with")
                .and_then(|w| str_of(w, "path"))
                .is_some_and(|p| p.lines().any(|l| l.trim() == "fuzz/corpus"))
    });
    if !corpus_cached {
        bad.push("ci.yml fuzz: fuzz/corpus is not cached between runs".into());
    }
    assert!(
        bad.is_empty(),
        "fuzz seeds and regressions must be committed and replayed:\n{}",
        bad.join("\n")
    );
}

/// Lot M3 (OpenSSF Scorecard, Binary-Artifacts): Scorecard counts a
/// committed executable or object file (by its magic bytes, or by a name
/// it gives them), and two `elf_audit` seeds were ELF files. They are
/// text now (`fuzz_api::text_seed`); no tracked file is one again.
/// Why Scorecard would count a file as a binary (`rel`, its first 4 KiB),
/// if it would.
fn binary_artifact(rel: &str, head: &[u8]) -> Option<&'static str> {
    // Scorecard's list of binary file names (checks/raw/binary_artifact.go)
    const NAMES: [&str; 27] = [
        "crx", "deb", "dex", "dey", "elf", "o", "a", "so", "macho", "iso", "class", "jar",
        "bundle", "dylib", "lib", "msi", "dll", "drv", "efi", "exe", "ocx", "pyc", "pyo", "par",
        "rpm", "wasm", "whl",
    ];
    // ELF; Mach-O (32, 64, either byte order) and fat Mach-O or a Java
    // class; WebAssembly; an ar archive (`.a`, `.deb`, `.lib`); Dalvik;
    // an rpm; a Chrome extension
    const MAGIC: [&[u8]; 11] = [
        b"\x7fELF",
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe",
        b"\0asm",
        b"!<arch>\n",
        b"dex\n",
        b"\xed\xab\xee\xdb",
        b"Cr24",
    ];
    // a PE file: `MZ`, and at the offset it gives, `PE\0\0`
    let pe = head.starts_with(b"MZ")
        && head
            .get(0x3c..0x40)
            .map(|o| u32::from_le_bytes(o.try_into().unwrap()) as usize)
            .and_then(|o| head.get(o..o.checked_add(4)?))
            == Some(b"PE\0\0".as_slice());
    let ext = Path::new(rel)
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase());
    if ext.is_some_and(|e| NAMES.contains(&e.as_str())) {
        Some("a binary file's name")
    } else if pe || MAGIC.iter().any(|m| head.starts_with(m)) {
        Some("an executable's or object file's magic bytes")
    } else {
        None
    }
}

/// Lot M3 (OpenSSF Scorecard, Binary-Artifacts): Scorecard counts a
/// committed executable or object file (by its magic bytes, or by a name
/// it gives them), and two `elf_audit` seeds were ELF files. They are
/// text now (`fuzz_api::text_seed`); no tracked file is one again.
#[test]
fn no_committed_file_is_an_executable_or_an_object_file() {
    use std::io::Read;
    // the check itself, on what it must and must not count
    let mut pe = b"MZ".to_vec();
    pe.resize(0x80, 0);
    pe[0x3c] = 0x40;
    pe[0x40..0x44].copy_from_slice(b"PE\0\0");
    let mut mz_text = pe.clone();
    mz_text[0x40..0x44].copy_from_slice(b"PEX\0");
    for (rel, head, counted) in [
        ("x/names-none.elf", b"# nn-fuzz-seed hex\n".as_slice(), true),
        ("x/lib.so", b"text".as_slice(), true),
        ("x/A.CLASS", b"text".as_slice(), true),
        ("x/seed.bin", b"\x7fELF\x02\x01\x01\0".as_slice(), true),
        (
            "x/seed.bin",
            b"\xcf\xfa\xed\xfe\x07\0\0\x01".as_slice(),
            true,
        ),
        ("x/seed.bin", b"\0asm\x01\0\0\0".as_slice(), true),
        ("x/seed.bin", b"!<arch>\ndebian-binary".as_slice(), true),
        ("x/seed.bin", pe.as_slice(), true),
        ("x/seed.bin", mz_text.as_slice(), false),
        ("x/seed.bin", b"MZ".as_slice(), false),
        (
            "x/names-none.elf.hex",
            b"# nn-fuzz-seed hex\n7f454c46".as_slice(),
            false,
        ),
        ("x/ELF.md", b"ELF files".as_slice(), false),
        ("x/seed.bin", b"\x16\x03\x01\x02\0\x01".as_slice(), false),
    ] {
        assert_eq!(
            binary_artifact(rel, head).is_some(),
            counted,
            "{rel} {head:?}"
        );
    }

    let root = repo_root();
    let mut bad = Vec::new();
    let mut read = 0;
    for rel in support::tracked_files() {
        let Ok(f) = fs::File::open(root.join(&rel)) else {
            continue;
        };
        let mut head = Vec::new();
        if f.take(4096).read_to_end(&mut head).is_err() {
            continue;
        }
        read += 1;
        if let Some(why) = binary_artifact(&rel, &head) {
            bad.push(format!("{rel}: {why}"));
        }
    }
    assert!(read > 500, "{read} files read");
    assert!(
        bad.is_empty(),
        "committed binaries (a fuzz seed goes in text form, `# nn-fuzz-seed hex`: \
         fuzz/README.md):\n{}",
        bad.join("\n")
    );
}

/// Lot M3: a fuzz input in text form (`*.hex` under `fuzz/seeds/<target>/`
/// or `fuzz/regressions/<target>/`) is one (`fuzz_api::text_seed`'s
/// header first), and its target decodes it (`fuzz_api::raw_and_decoded`):
/// libFuzzer gives the target the file as it is, and a target that does
/// not decode it fuzzes text.
#[test]
fn a_text_seed_is_decoded_by_its_target() {
    let root = repo_root();
    let header = "# nn-fuzz-seed hex";
    let api = read(&root.join("agent/src/fuzz_api.rs"));
    assert!(
        api.contains(&format!("pub const TEXT_SEED_HEADER: &str = \"{header}\";")),
        "fuzz_api's TEXT_SEED_HEADER is not `{header}`"
    );
    let mut seen = 0;
    let mut bad = Vec::new();
    for kind in ["seeds", "regressions"] {
        for target in subdirs(&root.join("fuzz").join(kind)) {
            let dir = root.join("fuzz").join(kind).join(&target);
            let mut texts: Vec<PathBuf> = fs::read_dir(&dir)
                .unwrap()
                .map(|e| e.unwrap().path())
                .filter(|p| p.extension().is_some_and(|x| x == "hex"))
                .collect();
            texts.sort();
            if texts.is_empty() {
                continue;
            }
            let src = read(&root.join(format!("fuzz/fuzz_targets/{target}.rs")));
            let code = support::strip_comments(&src);
            if !code.contains("raw_and_decoded(data,") {
                bad.push(format!(
                    "fuzz/fuzz_targets/{target}.rs: does not decode its text inputs \
                     (`fuzz_api::raw_and_decoded(data, …)`)"
                ));
            }
            for p in texts {
                seen += 1;
                if read(&p).lines().next() != Some(header) {
                    bad.push(format!("{}: its first line is not `{header}`", rel(&p)));
                }
            }
        }
    }
    assert!(seen >= 2, "{seen} text inputs");
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// SUP-023 (NN-AUD-407): the proofs ran weekly and on demand, so a PR that
/// weakened a proved bound merged with the proof red until the next
/// Monday. kani.yml runs on the pull requests that touch a file holding a
/// `#[kani::proof]` — those files and the workflow, no more, so the event
/// model and the rest of the agent do not start it — keeps its schedule,
/// and runs every harness.
#[test]
fn kani_runs_every_proof_on_the_prs_that_touch_it() {
    let root = repo_root();
    let mut files = Vec::new();
    let mut harnesses = Vec::new();
    // every member's sources (`cargo metadata`, lab PR 239: the list was
    // written here, and a proof in a crate it missed never ran)
    for krate in support::members().into_iter().map(|m| m.dir) {
        for file in files_under(&root.join(&krate).join("src"), &[".rs"], &[]) {
            let text = read(&file);
            let lines: Vec<&str> = text.lines().collect();
            let mut found = false;
            for (i, line) in lines.iter().enumerate() {
                if line.trim() != "#[kani::proof]" {
                    continue;
                }
                found = true;
                let name = lines[i + 1..]
                    .iter()
                    .find_map(|l| {
                        let l = l.trim();
                        let rest = l
                            .strip_prefix("fn ")
                            .or_else(|| l.strip_prefix("pub fn "))?;
                        rest.split('(').next().map(str::to_string)
                    })
                    .unwrap_or_else(|| panic!("{}: a #[kani::proof] without fn", rel(&file)));
                harnesses.push(name);
            }
            if found {
                files.push(rel(&file));
            }
        }
    }
    files.sort();
    assert!(files.len() >= 3, "proof files found: {files:?}");

    let kani_yml = root.join(".github/workflows/kani.yml");
    let wf = workflow_yaml(&kani_yml);
    let on = wf.get("on").expect("kani.yml has `on:`");
    let mut bad = Vec::new();
    if !on
        .get("schedule")
        .and_then(|s| s.as_sequence())
        .is_some_and(|s| s.iter().any(|e| str_of(e, "cron").is_some()))
    {
        bad.push("kani.yml: the weekly schedule is gone".to_string());
    }
    let pr = on.get("pull_request");
    let mut paths: Vec<String> = pr
        .and_then(|p| p.get("paths"))
        .and_then(|p| p.as_sequence())
        .map(|s| {
            s.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    paths.sort();
    let mut want = files.clone();
    want.push(".github/workflows/kani.yml".to_string());
    want.sort();
    if paths != want {
        bad.push(format!(
            "kani.yml: `on: pull_request: paths:` must be the proof files and the workflow\n  \
             have {paths:?}\n  want {want:?}"
        ));
    }
    let text = read(&kani_yml);
    for h in &harnesses {
        if !text.contains(&format!("--harness {h}")) {
            bad.push(format!("kani.yml: no step runs `--harness {h}`"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// External audit PROC-015 (NN-AUD-302): a release carries no test, debug
/// or demo feature. The release job builds with no `--features` (the agent
/// crate has no default feature: `agent/tests/build_features_cli.rs`), and
/// before its artefacts are uploaded it reads what each one carries:
/// `northnarrow-agent --build-features` must print `none` in the tarball,
/// the .deb and the .rpm, and nn-admin must have no `debug` subcommand.
#[test]
fn the_release_build_carries_no_lab_feature() {
    let file = repo_root().join(".github/workflows/release.yml");
    let wf = workflow_yaml(&file);
    let (_, package) = jobs(&wf)
        .into_iter()
        .find(|(name, _)| name == "package")
        .expect("release.yml has a package job");
    let steps = steps(&package);
    let runs: Vec<String> = steps
        .iter()
        .map(|s| str_of(s, "run").unwrap_or("").to_string())
        .collect();

    let mut builds = 0;
    for call in runs.iter().flat_map(|r| cargo_calls(r)) {
        let is_build = call.sub == "build"
            || (call.sub == "xtask" && call.args.first().is_some_and(|a| a == "build"));
        if !is_build {
            continue;
        }
        builds += 1;
        let featured =
            call.global.iter().chain(&call.args).any(|a| {
                a == "--all-features" || a.starts_with("--features") || a.starts_with("-F")
            });
        assert!(
            !featured,
            "release.yml: the release build must pass no cargo feature: {}",
            call.line
        );
    }
    assert!(
        builds >= 1,
        "release.yml: no release build found in the package job"
    );

    let check = runs
        .iter()
        .position(|r| r.contains("--build-features"))
        .expect("release.yml: no step checks the artefacts' --build-features");
    let script = &runs[check];
    for needle in [
        "dist/*.tar.gz",
        "dpkg-deb -x",
        "rpm2cpio",
        "!= none",
        "nn-admin\" --help",
        "debug( |$)",
    ] {
        assert!(
            script.contains(needle),
            "release.yml: the artefact check must use `{needle}`:\n{script}"
        );
    }
    let built = runs
        .iter()
        .position(|r| r.contains("mk-packages.sh"))
        .expect("release.yml builds the packages");
    let upload = steps
        .iter()
        .position(|s| str_of(s, "uses").is_some_and(|u| u.starts_with("actions/upload-artifact@")))
        .expect("the package job uploads its artefacts");
    assert!(
        built < check && check < upload,
        "release.yml: the artefact check runs after the packages are built and before the upload"
    );
}

/// Lab PR 268 (the review of #473, B4): the two scripts that pack a release
/// — the tarball's and the packages' — refuse an agent built with a lab
/// feature (`--build-features` not `none`: test-privileged exempts copies of
/// the binary from the restart rule, debug-trigger runs its BPF guard in
/// observe) and an nn-admin with the `debug` subcommand, before they copy
/// anything; only the lab's package check packs its lab build, with
/// `NN_PKG_LAB_FEATURES=1` (a warning), and no workflow sets it. Run under
/// bash in a scratch tree with stub binaries.
#[test]
fn the_release_scripts_refuse_a_lab_build() {
    use std::os::unix::fs::PermissionsExt;
    let base = Path::new(env!("CARGO_TARGET_TMPDIR")).join("release-scripts-lab-build");
    let _ = fs::remove_dir_all(&base);
    let ebpf = "agent-ebpf/target/bpfel-unknown-none/release/northnarrow-agent-ebpf";
    // the script in a tree of its own: (status, stderr)
    let run = |script: &str, case: &str, features: &str, debug: bool, opt_in: bool| {
        let tree = base.join(script).join(case);
        fs::create_dir_all(tree.join("deploy/release")).unwrap();
        fs::create_dir_all(tree.join("target/release")).unwrap();
        fs::create_dir_all(tree.join(ebpf).parent().unwrap()).unwrap();
        fs::copy(
            repo_root().join(format!("deploy/release/{script}")),
            tree.join(format!("deploy/release/{script}")),
        )
        .unwrap();
        fs::write(tree.join("Cargo.toml"), "version = \"0.0.0\"\n").unwrap();
        // the eBPF object and its stamp, older than the binaries
        for f in [ebpf.to_string(), format!("{ebpf}.buildhash")] {
            fs::write(tree.join(&f), "stamp").unwrap();
            let status = std::process::Command::new("touch")
                .args(["-d", "2020-01-01"])
                .arg(tree.join(&f))
                .status()
                .unwrap();
            assert!(status.success());
        }
        let stub = |name: &str, body: &str| {
            let p = tree.join("target/release").join(name);
            fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        };
        stub(
            "northnarrow-agent",
            &format!("[ \"$1\" = --build-features ] && echo '{features}'; exit 0"),
        );
        stub(
            "nn-admin",
            if debug {
                "printf 'Commands:\\n  status  x\\n  debug   y\\n'"
            } else {
                "printf 'Commands:\\n  status  x\\n'"
            },
        );
        stub("northnarrow-watchdog", "exit 0");
        stub("northnarrow-scan", "exit 0");
        let mut cmd = std::process::Command::new("bash");
        cmd.arg(tree.join(format!("deploy/release/{script}")))
            .arg(tree.join("out"))
            .env("NN_PKG_FORMATS", "none")
            .env_remove("NN_PKG_LAB_FEATURES");
        if opt_in {
            cmd.env("NN_PKG_LAB_FEATURES", "1");
        }
        let out = cmd.output().expect("bash runs");
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stderr).to_string(),
        )
    };
    for script in ["mk-tarball.sh", "mk-packages.sh"] {
        let tool = script.trim_end_matches(".sh");
        let (ok, err) = run(
            script,
            "lab-agent",
            "debug-trigger,test-privileged",
            false,
            false,
        );
        assert!(!ok, "{script}: a lab agent packed: {err}");
        assert!(
            err.contains(&format!(
                "{tool}: target/release/northnarrow-agent was built with lab features (debug-trigger,test-privileged)"
            )),
            "{script}: {err}"
        );
        let (ok, err) = run(script, "lab-admin", "none", true, false);
        assert!(!ok, "{script}: an nn-admin with debug packed: {err}");
        assert!(err.contains("has the debug subcommand"), "{script}: {err}");
        // a release build gets past the check (to whatever the scratch tree
        // lacks after it)
        let (_, err) = run(script, "release", "none", false, false);
        assert!(
            !err.contains("lab features") && !err.contains("debug subcommand"),
            "{script}: {err}"
        );
        assert!(
            err.contains("deploy/"),
            "{script}: not past the check: {err}"
        );
        // the lab's own opt-in: a warning, past the check
        let (_, err) = run(
            script,
            "opt-in",
            "debug-trigger,test-privileged",
            true,
            true,
        );
        assert!(
            err.contains("WARNING") && err.contains("NN_PKG_LAB_FEATURES=1"),
            "{script}: {err}"
        );
        assert!(!err.contains("rebuild with"), "{script}: {err}");
        // the check comes before anything is copied
        let text = read(&repo_root().join(format!("deploy/release/{script}")));
        let check = text.find("--build-features)").expect("the check");
        let first_copy = text.find("install -").expect("the first copy");
        assert!(check < first_copy, "{script}: the check after the copy");
    }
    // only the lab's package check opts in; no workflow does
    for file in workflow_files() {
        assert!(
            !read(&file).contains("NN_PKG_LAB_FEATURES"),
            "{}: a workflow packs lab features",
            rel(&file)
        );
    }
    assert!(
        read(&repo_root().join("deploy/lab/pkg/pkg-check.sh"))
            .contains("NN_PKG_LAB_FEATURES=1 NN_PKG_FORMATS=$fmt")
    );
}

// ---------------------------------------------------------------------------
// SUP-013, SUP-014, SUP-021: the BTF matrix and its third-party downloads.

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A BTFHub archive name run.sh accepts: `[A-Za-z0-9][A-Za-z0-9._+-]*.btf.tar.xz`.
fn is_btf_archive_name(s: &str) -> bool {
    s.strip_suffix(".btf.tar.xz").is_some_and(|stem| {
        stem.bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
            && stem
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
    })
}

/// The distro/version labels of deploy/btf-matrix/expected.tsv (not `host`).
fn btf_baseline_labels() -> Vec<String> {
    read(&repo_root().join("deploy/btf-matrix/expected.tsv"))
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split('\t').next())
        .filter(|k| *k != "host")
        .map(str::to_string)
        .collect()
}

/// SUP-014 (NN-AUD-399): the blobs fed to the product's BTF parser came
/// from the archive's moving `main`, chosen by whatever the API listed, and
/// a cached `.btf` was never checked again. blobs.sha256 pins one archive
/// commit and the sha256 of one archive per distro/version of the
/// baseline; run.sh downloads at that commit only and checks the digest.
#[test]
fn btf_matrix_blobs_are_pinned_by_commit_and_digest() {
    let root = repo_root();
    let pins = read(&root.join("deploy/btf-matrix/blobs.sha256"));
    let mut refs = Vec::new();
    let mut labels = Vec::new();
    let mut bad = Vec::new();
    for (i, line) in pins.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        match t.split_whitespace().collect::<Vec<_>>().as_slice() {
            ["ref", commit] => {
                if !is_lower_hex(commit, 40) {
                    bad.push(format!("line {}: ref `{commit}` is not a commit id", i + 1));
                }
                refs.push(commit.to_string());
            }
            [label, file, sha] => {
                if !label.contains('/') || label.contains("..") {
                    bad.push(format!("line {}: label `{label}`", i + 1));
                }
                if !is_btf_archive_name(file) {
                    bad.push(format!("line {}: archive name `{file}`", i + 1));
                }
                if !is_lower_hex(sha, 64) {
                    bad.push(format!("line {}: `{sha}` is not a sha256", i + 1));
                }
                if labels.contains(&label.to_string()) {
                    bad.push(format!("line {}: {label} pinned twice", i + 1));
                }
                labels.push(label.to_string());
            }
            _ => bad.push(format!("line {}: `{t}`", i + 1)),
        }
    }
    assert!(
        bad.is_empty(),
        "deploy/btf-matrix/blobs.sha256:\n{}",
        bad.join("\n")
    );
    assert_eq!(
        refs.len(),
        1,
        "blobs.sha256 needs exactly one `ref <commit>` line"
    );
    let mut pinned = labels.clone();
    pinned.sort();
    let mut baseline = btf_baseline_labels();
    baseline.sort();
    assert!(baseline.len() >= 9, "expected.tsv: {baseline:?}");
    assert_eq!(
        pinned, baseline,
        "every distro/version of expected.tsv has one pin, and no pin lacks a baseline"
    );

    let run = read(&root.join("deploy/btf-matrix/run.sh"));
    for needle in [
        "$ARCHIVE_RAW/$ARCHIVE_REF/",
        "?ref=$ARCHIVE_REF",
        "sha256sum",
        "tar -xJOf",
    ] {
        assert!(
            run.contains(needle),
            "deploy/btf-matrix/run.sh must use `{needle}`"
        );
    }
    for needle in ["raw/main", "tar -xJf"] {
        assert!(
            !run.contains(needle),
            "deploy/btf-matrix/run.sh must not use `{needle}`"
        );
    }
}

/// SUP-021 (NN-AUD-405): `-H "Authorization: Bearer $GITHUB_TOKEN"` put the
/// token in curl's argv, readable by any local user in /proc/<pid>/cmdline.
/// run.sh passes it as `-H @<(printf …)`, and only `--refresh` needs it: the
/// workflow gives the matrix step no token at all.
#[test]
fn btf_matrix_sends_no_token_on_a_command_line() {
    let root = repo_root();
    let run = read(&root.join("deploy/btf-matrix/run.sh"));
    let mut auth = 0;
    for (i, line) in run.lines().enumerate() {
        let code = line.split(" #").next().unwrap_or(line);
        if code.trim_start().starts_with('#') || !code.contains("Authorization") {
            continue;
        }
        auth += 1;
        assert!(
            code.contains("-H @<(printf 'Authorization: Bearer %s\\n' \"$GITHUB_TOKEN\")"),
            "run.sh:{}: the token goes in a header curl reads from a file descriptor: {line}",
            i + 1
        );
    }
    assert_eq!(auth, 1, "run.sh: one place sends the token");
    assert!(
        !run.contains("${GITHUB_TOKEN:+-H"),
        "run.sh: the old argv header is back"
    );

    let wf = workflow_yaml(&root.join(".github/workflows/btf-matrix.yml"));
    for (job, body) in jobs(&wf) {
        for step in steps(&body) {
            let env = support::yaml::to_string(&step.get("env").cloned().unwrap_or_default())
                .unwrap_or_default();
            assert!(
                !env.contains("GITHUB_TOKEN") && !env.contains("GH_TOKEN"),
                "btf-matrix.yml: job {job}: a step is given a token it does not need:\n{env}"
            );
        }
    }
}

/// SUP-014 with SUP-022: the blob cache was restored from any
/// `btfhub-blobs-` key. It is keyed by the pin file, never restored from
/// another key, and run.sh checks every cached archive anyway; the workflow
/// runs run.sh's offline tests before the matrix.
#[test]
fn btf_matrix_cache_is_keyed_by_the_pins() {
    let wf = workflow_yaml(&repo_root().join(".github/workflows/btf-matrix.yml"));
    let (_, matrix) = jobs(&wf)
        .into_iter()
        .find(|(name, _)| name == "matrix")
        .expect("btf-matrix.yml has a matrix job");
    let steps = steps(&matrix);
    let cache = steps
        .iter()
        .find(|s| {
            s.get("with")
                .and_then(|w| str_of(w, "path"))
                .is_some_and(|p| p.contains("nn-btf-matrix"))
        })
        .expect("btf-matrix.yml caches the BTFHub blobs");
    let with = cache.get("with").unwrap();
    let key = str_of(with, "key").unwrap_or("");
    assert!(
        key.contains("hashFiles('deploy/btf-matrix/blobs.sha256')"),
        "the blob cache key must hash the pin file: {key}"
    );
    assert!(
        with.get("restore-keys").is_none(),
        "the blob cache must not be restored from another key"
    );
    let runs: Vec<&str> = steps
        .iter()
        .map(|s| str_of(s, "run").unwrap_or(""))
        .collect();
    let selftest = runs
        .iter()
        .position(|r| r.contains("deploy/btf-matrix/run-test.sh"))
        .expect("btf-matrix.yml runs deploy/btf-matrix/run-test.sh");
    let matrix_run = runs
        .iter()
        .position(|r| r.contains("deploy/btf-matrix/run.sh"))
        .expect("btf-matrix.yml runs deploy/btf-matrix/run.sh");
    assert!(selftest < matrix_run, "run-test.sh runs before the matrix");
}

/// SUP-013 (NN-AUD-398), SUP-014, SUP-021: run.sh's behaviour, offline:
/// stub curl, gh and agent first on PATH, a local directory as the archive.
/// Among its cases: a distro/version of the baseline without a blob fails
/// the run (it was a green "n/a"); a blob or a cached copy whose digest is
/// not the pinned one is refused and leaves nothing in the cache; a name
/// with `/`, `..` or a space is refused; an archive with any member but
/// `<kernel>.btf` (`../x`, a link, a second file) is refused; the token is
/// on no command line.
#[cfg(unix)]
#[test]
fn btf_matrix_script_passes_its_offline_tests() {
    use std::os::unix::fs::PermissionsExt;
    let script = repo_root().join("deploy/btf-matrix/run-test.sh");
    for f in ["deploy/btf-matrix/run-test.sh", "deploy/btf-matrix/run.sh"] {
        let mode = fs::metadata(repo_root().join(f))
            .unwrap_or_else(|e| panic!("{f}: {e}"))
            .permissions()
            .mode();
        assert!(
            mode & 0o111 != 0,
            "{f} must be executable (the workflow runs it)"
        );
    }
    let out = std::process::Command::new("bash")
        .arg(&script)
        .env_remove("GITHUB_TOKEN")
        .env_remove("GH_TOKEN")
        .output()
        .expect("bash runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "deploy/btf-matrix/run-test.sh failed:\n{stdout}\n{stderr}"
    );
    let cases = stdout.lines().filter(|l| l.starts_with("ok - ")).count();
    assert!(cases >= 11, "run-test.sh ran {cases} cases:\n{stdout}");
    assert!(stdout.contains("0 assertion(s) failed"), "{stdout}");
}

// ---------------------------------------------------------------------------
// SUP-024: release governance.

fn release_jobs() -> support::yaml::Value {
    workflow_yaml(&repo_root().join(".github/workflows/release.yml"))
        .get("jobs")
        .cloned()
        .expect("release.yml has jobs")
}

fn needs_of(job: &support::yaml::Value) -> Vec<String> {
    match job.get("needs") {
        Some(support::yaml::Value::String(s)) => vec![s.clone()],
        Some(support::yaml::Value::Sequence(v)) => v
            .iter()
            .filter_map(|x| x.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

fn job_runs(job: &support::yaml::Value) -> String {
    steps(job)
        .iter()
        .filter_map(|s| str_of(s, "run").map(str::to_string))
        .collect::<Vec<_>>()
        .join("\n")
}

/// SUP-024 (NN-AUD-408): nothing checked who made the tag. `verify-tag`
/// (tags only, read-only) runs .github/scripts/verify-release-tag.sh on the
/// tag object as pushed; `package` waits for it on a tag, and every other
/// job depends on it through `needs`.
#[test]
fn tag_signature_is_verified_before_package() {
    let root = repo_root();
    let jobs = release_jobs();
    let vt = jobs
        .get("verify-tag")
        .expect("release.yml has a verify-tag job");
    assert!(
        str_of(vt, "if").is_some_and(|c| c.contains("startsWith(github.ref, 'refs/tags/v')")),
        "verify-tag runs on v* tags"
    );
    let perms = vt
        .get("permissions")
        .expect("verify-tag declares its permissions");
    assert_eq!(str_of(perms, "contents"), Some("read"));
    assert!(
        perms.get("id-token").is_none(),
        "verify-tag needs no OIDC token"
    );
    assert!(
        vt.get("environment").is_none(),
        "verify-tag needs no secret"
    );
    let script = job_runs(vt);
    for needle in [
        "refs/tags/$TAG:refs/tags/$TAG",
        ".github/scripts/verify-release-tag.sh verify \"$TAG\" \"$GITHUB_SHA\"",
    ] {
        assert!(
            script.contains(needle),
            "verify-tag must run `{needle}`:\n{script}"
        );
    }

    let package = jobs.get("package").expect("release.yml has a package job");
    assert!(
        needs_of(package).contains(&"verify-tag".to_string()),
        "package needs verify-tag"
    );
    let cond = str_of(package, "if").unwrap_or("");
    for needle in [
        "needs.verify-tag.result == 'success'",
        "needs.verify-tag.result == 'skipped' && !startsWith(github.ref, 'refs/tags/v')",
    ] {
        assert!(
            cond.contains(needle),
            "package's `if` must hold `{needle}`, got `{cond}`"
        );
    }

    // every job but verify-tag reaches it through needs
    let names: Vec<String> = jobs
        .as_mapping()
        .unwrap()
        .keys()
        .filter_map(|k| k.as_str().map(str::to_string))
        .collect();
    for name in names.iter().filter(|n| *n != "verify-tag") {
        let mut seen = Vec::new();
        let mut stack = needs_of(jobs.get(name.as_str()).unwrap());
        while let Some(n) = stack.pop() {
            if seen.contains(&n) {
                continue;
            }
            stack.extend(needs_of(
                jobs.get(n.as_str()).unwrap_or(&support::yaml::Value::Null),
            ));
            seen.push(n);
        }
        assert!(
            seen.contains(&"verify-tag".to_string()),
            "release.yml: job {name} does not depend on verify-tag"
        );
    }
    let publish_if = jobs
        .get("publish")
        .and_then(|j| str_of(j, "if"))
        .unwrap_or("");
    assert!(
        publish_if.contains("needs.verify-tag.result == 'success'"),
        "publish requires a verified tag, got `{publish_if}`"
    );

    let check = root.join(".github/scripts/verify-release-tag.sh");
    assert!(
        check.is_file(),
        ".github/scripts/verify-release-tag.sh is missing"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&check).unwrap().permissions().mode();
        assert!(
            mode & 0o111 != 0,
            "verify-release-tag.sh must be executable"
        );
    }
    assert!(
        root.join(".github/allowed_signers").is_file(),
        ".github/allowed_signers is missing"
    );
}

/// SUP-024: `gh release upload … --clobber` replaced published assets
/// without a trace. No workflow passes --clobber; only `publish` touches a
/// release, creates it as a draft with the tag required to exist, refuses
/// a release that already has assets, and holds `contents: write` alone.
#[test]
fn release_publish_does_not_clobber() {
    for file in workflow_files() {
        let wf = workflow_yaml(&file);
        for (job, body) in jobs(&wf) {
            let runs = job_runs(&body);
            assert!(
                !runs.contains("--clobber"),
                "{}: job {job} passes --clobber",
                rel(&file)
            );
            let is_publish = rel(&file) == ".github/workflows/release.yml" && job == "publish";
            assert!(
                is_publish || !runs.contains("gh release"),
                "{}: job {job} touches a release; only release.yml's publish may",
                rel(&file)
            );
        }
    }
    let jobs = release_jobs();
    let publish = jobs.get("publish").expect("release.yml has a publish job");
    assert!(
        str_of(publish, "if").is_some_and(|c| c.contains("startsWith(github.ref, 'refs/tags/v')")),
        "publish runs on v* tags only"
    );
    assert_eq!(str_of(publish, "environment"), Some("release-signing"));
    let perms = publish
        .get("permissions")
        .and_then(|p| p.as_mapping())
        .expect("publish declares its permissions");
    assert_eq!(
        perms.len(),
        1,
        "publish holds `contents: write` and nothing else"
    );
    assert_eq!(
        str_of(publish.get("permissions").unwrap(), "contents"),
        Some("write")
    );
    assert!(
        needs_of(publish).contains(&"sign".to_string()),
        "publish waits for sign"
    );
    let runs = job_runs(publish);
    for needle in [
        "--json assets --jq '.assets | length'",
        "gh release create \"$TAG\" --verify-tag --draft",
        "gh release upload \"$TAG\" dist/*",
        "gh release edit \"$TAG\" --draft=false",
        "sha256sum -c SHA256SUMS",
    ] {
        assert!(
            runs.contains(needle),
            "publish must run `{needle}`:\n{runs}"
        );
    }
    assert!(
        !steps(publish)
            .iter()
            .any(|s| str_of(s, "uses").is_some_and(|u| u.starts_with("actions/checkout@"))),
        "publish checks nothing out"
    );
}

/// SUP-024: `sign` held `contents: write` next to `id-token: write` for
/// the publish step alone. No job of any workflow holds both.
#[test]
fn no_job_holds_contents_write_and_id_token() {
    let mut seen = 0;
    for file in workflow_files() {
        let wf = workflow_yaml(&file);
        let top = wf.get("permissions").cloned().unwrap_or_default();
        for (job, body) in jobs(&wf) {
            let perms = body
                .get("permissions")
                .cloned()
                .unwrap_or_else(|| top.clone());
            let level = |scope: &str| perms.get(scope).and_then(|v| v.as_str()).unwrap_or("");
            if level("id-token") == "write" {
                seen += 1;
            }
            assert!(
                !(level("contents") == "write" && level("id-token") == "write"),
                "{}: job {job} holds contents: write and id-token: write",
                rel(&file)
            );
            assert!(
                perms.as_str().is_none_or(|p| p != "write-all"),
                "{}: job {job}: write-all",
                rel(&file)
            );
        }
    }
    assert!(
        seen >= 1,
        "no job asks for an OIDC token (release.yml's sign should)"
    );
}

/// SUP-024: .github/allowed_signers is git's gpg.ssh.allowedSignersFile.
/// Each key is an SSH public key limited to the "git" namespace; the file
/// says so when it lists none (every tag then stops at verify-tag), and
/// stops saying so once it lists one.
#[test]
fn allowed_signers_lists_only_git_namespaced_ssh_keys() {
    const KEY_TYPES: [&str; 7] = [
        "ssh-ed25519",
        "sk-ssh-ed25519@openssh.com",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ecdsa-sha2-nistp256@openssh.com",
        "ssh-rsa",
    ];
    let text = read(&repo_root().join(".github/allowed_signers"));
    let mut keys = 0;
    let mut bad = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        keys += 1;
        let f: Vec<&str> = t.split_whitespace().collect();
        let ok = f.len() >= 4
            && f[1].split(',').any(|o| o == "namespaces=\"git\"")
            && KEY_TYPES.contains(&f[2])
            && f[3].starts_with("AAAA")
            && f[3]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/=".contains(&b));
        if !ok {
            bad.push(format!(
                "line {}: expected `<principal> namespaces=\"git\" <key type> <base64 key>`: {t}",
                i + 1
            ));
        }
    }
    assert!(
        bad.is_empty(),
        ".github/allowed_signers:\n{}",
        bad.join("\n")
    );
    assert_eq!(
        keys == 0,
        text.contains("NO KEY IS LISTED YET"),
        ".github/allowed_signers: the `NO KEY IS LISTED YET` note must match the file ({keys} key(s))"
    );
}

/// SUP-024 (lot 394): the header of .github/allowed_signers publishes the
/// SHA256 fingerprint of each listed key, and of no other key: after a
/// rotation it names the new key, never the one removed.
#[cfg(unix)]
#[test]
fn allowed_signers_header_names_the_listed_keys_fingerprints() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let text = read(&repo_root().join(".github/allowed_signers"));
    let mut listed = Vec::new();
    for t in text
        .lines()
        .map(str::trim)
        .filter(|t| !t.is_empty() && !t.starts_with('#'))
    {
        let key: Vec<&str> = t.split_whitespace().skip(2).take(2).collect();
        let mut child = Command::new("ssh-keygen")
            .args(["-l", "-E", "sha256", "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("ssh-keygen runs");
        child
            .stdin
            .take()
            .expect("ssh-keygen's stdin")
            .write_all(format!("{}\n", key.join(" ")).as_bytes())
            .expect("the key is written to ssh-keygen");
        let out = child.wait_with_output().expect("ssh-keygen ends");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "ssh-keygen -l refused a listed key: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let fp = stdout
            .split_whitespace()
            .nth(1)
            .filter(|f| f.starts_with("SHA256:"))
            .unwrap_or_else(|| panic!("no SHA256 fingerprint in: {stdout}"));
        listed.push(fp.to_string());
    }
    let named: Vec<&str> = text
        .lines()
        .filter(|l| l.trim_start().starts_with('#'))
        .flat_map(str::split_whitespace)
        .filter_map(|w| w.find("SHA256:").map(|i| &w[i..]))
        .map(|w| w.trim_end_matches(|c: char| !(c.is_ascii_alphanumeric() || c == '+' || c == '/')))
        .collect();
    for fp in &listed {
        assert!(
            named.contains(&fp.as_str()),
            ".github/allowed_signers: the header does not name the listed key {fp}"
        );
    }
    for fp in &named {
        assert!(
            listed.iter().any(|l| l == fp),
            ".github/allowed_signers: the header names {fp}, which no listed key has"
        );
    }
}

/// SUP-024: the tag check itself, on a scratch repository with throwaway
/// keys: a tag signed by the listed key passes; another key, an unsigned,
/// lightweight, renamed or altered tag, a tag of another commit, an
/// expired key, a key of another namespace and an empty list are refused.
/// With the committed list empty, the real check refuses every tag.
#[cfg(unix)]
#[test]
fn release_tag_check_accepts_only_listed_signers() {
    let root = repo_root();
    let script = root.join(".github/scripts/verify-release-tag.sh");
    let out = std::process::Command::new("bash")
        .arg(&script)
        .arg("selftest")
        .output()
        .expect("bash runs");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "verify-release-tag.sh selftest failed:\n{stdout}\n{stderr}"
    );
    assert!(stdout.contains("selftest: all cases passed"), "{stdout}");
    let cases = stdout.lines().filter(|l| l.starts_with("ok - ")).count();
    assert!(cases >= 13, "the selftest ran {cases} cases:\n{stdout}");

    let signers = read(&root.join(".github/allowed_signers"));
    if signers
        .lines()
        .all(|l| l.trim().is_empty() || l.trim_start().starts_with('#'))
    {
        let out = std::process::Command::new("bash")
            .arg(&script)
            .args(["verify", "v0.0.0", &"0".repeat(40)])
            .current_dir(&root)
            .output()
            .expect("bash runs");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(1),
            "an empty list must refuse: {stderr}"
        );
        assert!(stderr.contains("lists no key"), "{stderr}");
    }
}

// ---------------------------------------------------------------------------
// Code scanning (lot codeql): CodeQL, advanced setup, `.github/workflows/codeql.yml`.

/// The CodeQL language whose extractor reads the tracked file `path`, if
/// any: the languages GitHub's language detection reports for code
/// scanning (`actions` for the workflows and the action metadata files).
fn codeql_language(path: &str) -> Option<&'static str> {
    let name = path.rsplit('/').next().unwrap_or(path);
    let yaml = name.ends_with(".yml") || name.ends_with(".yaml");
    if (yaml && path.starts_with(".github/workflows/"))
        || name == "action.yml"
        || name == "action.yaml"
    {
        return Some("actions");
    }
    let (_, ext) = name.rsplit_once('.')?;
    Some(match ext {
        "rs" => "rust",
        "py" | "pyi" => "python",
        "c" | "h" | "cc" | "cpp" | "cxx" | "hh" | "hpp" | "hxx" => "c-cpp",
        "js" | "jsx" | "mjs" | "cjs" | "ts" | "tsx" | "mts" | "cts" | "vue" => {
            "javascript-typescript"
        }
        "go" => "go",
        "java" | "kt" | "kts" => "java-kotlin",
        "cs" | "cshtml" | "razor" => "csharp",
        "rb" | "erb" => "ruby",
        "swift" => "swift",
        _ => return None,
    })
}

#[test]
fn the_codeql_language_of_a_file() {
    for (path, want) in [
        (".github/workflows/ci.yml", Some("actions")),
        (".github/workflows/x.yaml", Some("actions")),
        ("deploy/act/action.yml", Some("actions")),
        ("action.yaml", Some("actions")),
        (".github/dependabot.yml", None),
        ("deploy/lab/cloud-init.yml", None),
        ("agent/src/main.rs", Some("rust")),
        ("deploy/lab/lib/lab-records.py", Some("python")),
        ("stubs/x.pyi", Some("python")),
        ("deploy/lab/epg/epg-probe.c", Some("c-cpp")),
        ("a.h", Some("c-cpp")),
        ("a.cc", Some("c-cpp")),
        ("a.cpp", Some("c-cpp")),
        ("a.cxx", Some("c-cpp")),
        ("a.hh", Some("c-cpp")),
        ("a.hpp", Some("c-cpp")),
        ("a.hxx", Some("c-cpp")),
        ("a.js", Some("javascript-typescript")),
        ("a.jsx", Some("javascript-typescript")),
        ("a.mjs", Some("javascript-typescript")),
        ("a.cjs", Some("javascript-typescript")),
        ("a.ts", Some("javascript-typescript")),
        ("a.tsx", Some("javascript-typescript")),
        ("a.mts", Some("javascript-typescript")),
        ("a.cts", Some("javascript-typescript")),
        ("a.vue", Some("javascript-typescript")),
        ("a.go", Some("go")),
        ("a.java", Some("java-kotlin")),
        ("a.kt", Some("java-kotlin")),
        ("a.kts", Some("java-kotlin")),
        ("a.cs", Some("csharp")),
        ("a.cshtml", Some("csharp")),
        ("a.razor", Some("csharp")),
        ("a.rb", Some("ruby")),
        ("a.erb", Some("ruby")),
        ("a.swift", Some("swift")),
        ("deploy/install.sh", None),
        ("README.md", None),
        ("Makefile", None),
        ("rs", None),
    ] {
        assert_eq!(codeql_language(path), want, "{path}");
    }
}

/// The `key: value` mapping of `v` as (key, value) strings, in order (a
/// number or a boolean as YAML writes it).
fn string_pairs(v: Option<&support::yaml::Value>) -> Vec<(String, String)> {
    let scalar = |v: &support::yaml::Value| match v {
        support::yaml::Value::String(s) => s.clone(),
        support::yaml::Value::Number(n) => n.to_string(),
        support::yaml::Value::Bool(b) => b.to_string(),
        other => format!("{other:?}"),
    };
    v.and_then(|m| m.as_mapping())
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.as_str().unwrap_or("?").to_string(), scalar(v)))
                .collect()
        })
        .unwrap_or_default()
}

fn pairs(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

const CODEQL_CONFIG: &str = ".github/codeql/codeql-config.yml";

/// Review of #496: what CodeQL does not scan — only directories no
/// shipped build contains: each workspace member's cargo integration tests
/// (`<member>/tests`, when it has any), the fuzz harness and the lab's
/// tooling.
fn codeql_unshipped_dirs(tracked: &[String]) -> Vec<String> {
    let mut dirs: Vec<String> = support::members()
        .into_iter()
        .map(|m| format!("{}/tests", m.dir))
        .filter(|d| tracked.iter().any(|f| f.starts_with(&format!("{d}/"))))
        .collect();
    dirs.extend(["fuzz".to_string(), "deploy/lab".to_string()]);
    dirs.sort();
    dirs
}

/// Lot codeql: CodeQL analyses every language of what ships, without a
/// build and with the `security-extended` suite, on every pull request to
/// main (no path filter: none can skip it), every push to main and
/// weekly, a pull request's completely (not diff-informed). Its config
/// ignores only the directories no shipped build contains. Review of #496:
/// the analysis runs with a read-only token and keeps its SARIF as an
/// artifact; a second job, which runs nothing of the tree, uploads it with
/// `security-events: write`. The Rust job installs
/// every toolchain the tree pins (each `rust-toolchain.toml`), fetches
/// every cargo project from its lockfile and fails if the extraction
/// changed one; the CodeQL bundle the runner caches is not deleted, and no
/// step is handed a secret.
#[test]
fn codeql_scans_every_language_of_the_tree() {
    const FILE: &str = ".github/workflows/codeql.yml";
    let path = repo_root().join(FILE);
    let text = read(&path);
    let wf = workflow_yaml(&path);
    let tracked = support::tracked_files();

    // When: every pull request and push to main, and a weekly schedule.
    let on = wf.get("on").expect("codeql.yml: `on:`");
    for event in ["pull_request", "push"] {
        let cfg = on
            .get(event)
            .and_then(|c| c.as_mapping())
            .unwrap_or_else(|| panic!("{FILE}: no `on.{event}` mapping"));
        let keys: Vec<&str> = cfg.keys().filter_map(|k| k.as_str()).collect();
        assert_eq!(
            keys,
            ["branches"],
            "{FILE}: on.{event} filters on more than the branch"
        );
        let branches: Vec<&str> = cfg
            .get("branches")
            .and_then(|b| b.as_sequence())
            .map(|b| b.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        assert_eq!(branches, ["main"], "{FILE}: on.{event}.branches");
    }
    assert!(
        on.get("pull_request_target").is_none(),
        "{FILE}: pull_request_target runs a fork's code with this repository's token"
    );
    let crons: Vec<&str> = on
        .get("schedule")
        .and_then(|s| s.as_sequence())
        .map(|s| s.iter().filter_map(|e| str_of(e, "cron")).collect())
        .unwrap_or_default();
    assert_eq!(crons.len(), 1, "{FILE}: one schedule");
    let fields: Vec<&str> = crons[0].split_whitespace().collect();
    assert!(
        fields.len() == 5
            && fields[2] == "*"
            && fields[3] == "*"
            && fields[4].len() == 1
            && fields[4].bytes().all(|b| (b'0'..=b'6').contains(&b))
            && fields[..2]
                .iter()
                .all(|f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit())),
        "{FILE}: the schedule is weekly (one minute, hour and weekday), not `{}`",
        crons[0]
    );

    // The token: read everywhere; security-events: write on upload alone.
    assert_eq!(
        string_pairs(wf.get("permissions")),
        pairs(&[("contents", "read")]),
        "{FILE}: top-level permissions"
    );
    let all = jobs(&wf);
    assert_eq!(
        all.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
        ["analyze", "upload"],
        "{FILE}: the jobs"
    );
    let (job, upload) = (&all[0].1, &all[1].1);
    assert_eq!(
        string_pairs(job.get("permissions")),
        pairs(&[("contents", "read")]),
        "{FILE}: analyze runs the dependency tree's code: read only"
    );
    assert_eq!(
        string_pairs(job.get("env")),
        pairs(&[("CODEQL_ACTION_DIFF_INFORMED_QUERIES", "false")]),
        "{FILE}: analyze's env: a complete analysis (the upload, in another job, cannot filter a diff-informed one)"
    );
    assert!(upload.get("env").is_none(), "{FILE}: upload's env");
    assert_eq!(
        string_pairs(upload.get("permissions")),
        pairs(&[("contents", "read"), ("security-events", "write")]),
        "{FILE}: upload's permissions"
    );
    for (name, j) in [("analyze", job), ("upload", upload)] {
        assert!(
            j.get("timeout-minutes").and_then(|t| t.as_u64()).is_some(),
            "{FILE}: {name} has a timeout"
        );
        assert!(
            j.get("continue-on-error").is_none(),
            "{FILE}: a failed {name} fails the run"
        );
    }
    assert_eq!(
        str_of(upload, "needs"),
        Some("analyze"),
        "{FILE}: upload needs analyze"
    );
    assert_eq!(
        str_of(upload, "if"),
        Some("${{ !cancelled() }}"),
        "{FILE}: each language is uploaded even if another one failed"
    );

    // What: every language of the shipped tree, each without a build. The
    // config ignores the unshipped directories and nothing else.
    let config = workflow_yaml(&repo_root().join(CODEQL_CONFIG));
    let config_keys: Vec<&str> = config
        .as_mapping()
        .map(|m| m.keys().filter_map(|k| k.as_str()).collect())
        .unwrap_or_default();
    assert_eq!(
        config_keys,
        ["name", "paths-ignore"],
        "{CODEQL_CONFIG}: its keys"
    );
    let mut ignored: Vec<String> = config
        .get("paths-ignore")
        .and_then(|p| p.as_sequence())
        .map(|p| {
            p.iter()
                .filter_map(|v| v.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let listed = ignored.len();
    ignored.sort();
    ignored.dedup();
    assert_eq!(ignored.len(), listed, "{CODEQL_CONFIG}: a path twice");
    let unshipped = codeql_unshipped_dirs(&tracked);
    assert!(unshipped.len() >= 4, "{unshipped:?}");
    assert_eq!(
        ignored, unshipped,
        "{CODEQL_CONFIG}: paths-ignore lists exactly the directories no shipped build contains"
    );
    let mut scanned = Vec::new();
    let include = job
        .get("strategy")
        .and_then(|s| s.get("matrix"))
        .and_then(|m| m.get("include"))
        .and_then(|i| i.as_sequence())
        .expect("codeql.yml: strategy.matrix.include");
    for entry in include {
        let lang = str_of(entry, "language").expect("a matrix entry names its language");
        assert_eq!(
            str_of(entry, "build-mode"),
            Some("none"),
            "{FILE}: {lang} is analysed without a build"
        );
        scanned.push(lang.to_string());
    }
    let mut sorted = scanned.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), scanned.len(), "{FILE}: a language twice");
    let present: std::collections::BTreeSet<String> = tracked
        .iter()
        .filter(|f| !ignored.iter().any(|d| f.starts_with(&format!("{d}/"))))
        .filter_map(|f| codeql_language(f))
        .map(str::to_string)
        .collect();
    assert!(present.contains("rust") && present.contains("actions"));
    assert_eq!(
        sorted,
        present.into_iter().collect::<Vec<_>>(),
        "{FILE}: the languages scanned are those of the tracked files outside {CODEQL_CONFIG}'s paths-ignore"
    );
    let uploaded: Vec<String> = upload
        .get("strategy")
        .and_then(|s| s.get("matrix"))
        .and_then(|m| m.get("language"))
        .and_then(|l| l.as_sequence())
        .map(|l| {
            l.iter()
                .filter_map(|v| v.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let mut uploaded_sorted = uploaded.clone();
    uploaded_sorted.sort();
    assert_eq!(
        uploaded_sorted, sorted,
        "{FILE}: upload's languages are analyze's"
    );

    // How: checkout, init, analyze (kept), the artifact last; one pin for
    // every codeql-action step.
    let job_steps = steps(job);
    let uses_in = |all: &[support::yaml::Value], prefix: &str| -> usize {
        let found: Vec<usize> = all
            .iter()
            .enumerate()
            .filter(|(_, s)| str_of(s, "uses").is_some_and(|u| u.starts_with(prefix)))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(found.len(), 1, "{FILE}: one `{prefix}` step");
        found[0]
    };
    let checkout = uses_in(&job_steps, "actions/checkout@");
    let init_at = uses_in(&job_steps, "github/codeql-action/init@");
    let analyze_at = uses_in(&job_steps, "github/codeql-action/analyze@");
    let keep_at = uses_in(&job_steps, "actions/upload-artifact@");
    assert!(
        checkout < init_at && init_at < analyze_at && keep_at == job_steps.len() - 1,
        "{FILE}: checkout, then init, then analyze; the artifact last"
    );
    let (init, analyze, keep) = (
        &job_steps[init_at],
        &job_steps[analyze_at],
        &job_steps[keep_at],
    );
    let pin = |s: &support::yaml::Value| {
        str_of(s, "uses")
            .and_then(|u| u.split_once('@'))
            .map(|(_, r)| r.to_string())
    };
    assert_eq!(
        pin(init),
        pin(analyze),
        "{FILE}: init and analyze at one commit"
    );
    let with = |s: &support::yaml::Value| string_pairs(s.get("with"));
    assert_eq!(
        with(init),
        pairs(&[
            ("languages", "${{ matrix.language }}"),
            ("build-mode", "${{ matrix.build-mode }}"),
            ("config-file", &format!("./{CODEQL_CONFIG}")),
            ("queries", "security-extended"),
        ]),
        "{FILE}: init's inputs"
    );
    let category = "/language:${{ matrix.language }}";
    let analyze_with = with(analyze);
    assert_eq!(
        analyze_with
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>(),
        ["category", "upload", "output"],
        "{FILE}: analyze's inputs"
    );
    assert_eq!(analyze_with[0].1, category, "{FILE}: analyze's category");
    assert_eq!(
        analyze_with[1].1, "never",
        "{FILE}: analyze uploads nothing"
    );
    let sarif_dir = analyze_with[2].1.clone();
    let artifact = "codeql-sarif-${{ matrix.language }}";
    assert_eq!(
        with(keep),
        pairs(&[
            ("name", artifact),
            ("path", &sarif_dir),
            ("if-no-files-found", "error"),
            ("retention-days", "5"),
        ]),
        "{FILE}: the artifact holds analyze's SARIF"
    );
    for s in [init, analyze, keep] {
        assert!(s.get("continue-on-error").is_none(), "{FILE}: {s:?}");
        assert!(s.get("if").is_none(), "{FILE}: every language runs {s:?}");
    }

    // The upload: checkout, the artifact, upload-sarif; nothing else.
    let up_steps = steps(upload);
    assert_eq!(up_steps.len(), 3, "{FILE}: upload's steps");
    let (co, dl, up) = (&up_steps[0], &up_steps[1], &up_steps[2]);
    assert!(str_of(co, "uses").is_some_and(|u| u.starts_with("actions/checkout@")));
    assert_eq!(
        with(co),
        pairs(&[("persist-credentials", "false")]),
        "{FILE}: upload checks out this commit, nothing more"
    );
    assert!(str_of(dl, "uses").is_some_and(|u| u.starts_with("actions/download-artifact@")));
    assert_eq!(
        with(dl),
        pairs(&[("name", artifact), ("path", &sarif_dir)]),
        "{FILE}: upload downloads analyze's artifact"
    );
    assert!(
        str_of(up, "uses").is_some_and(|u| u.starts_with("github/codeql-action/upload-sarif@")),
        "{FILE}: upload's last step is upload-sarif"
    );
    assert_eq!(pin(up), pin(init), "{FILE}: upload-sarif at init's commit");
    assert_eq!(
        with(up),
        pairs(&[("sarif_file", &sarif_dir), ("category", category)]),
        "{FILE}: upload-sarif's inputs"
    );
    for s in &up_steps {
        assert!(
            s.get("run").is_none() && s.get("if").is_none() && s.get("continue-on-error").is_none(),
            "{FILE}: upload {s:?}"
        );
    }

    // Rust: the pinned toolchains, every lockfile fetched and left as it was.
    let rust_only = |s: &support::yaml::Value| str_of(s, "if") == Some("matrix.language == 'rust'");
    let lockfiles: Vec<String> = tracked
        .iter()
        .filter(|f| *f == "Cargo.lock" || f.ends_with("/Cargo.lock"))
        .cloned()
        .collect();
    assert!(lockfiles.len() >= 3, "{lockfiles:?}");
    let prepare = job_steps[..init_at]
        .iter()
        .find(|s| rust_only(s) && str_of(s, "run").is_some_and(|r| r.contains("cargo fetch")))
        .unwrap_or_else(|| panic!("{FILE}: a Rust step before init fetches the dependencies"));
    let lines = script_lines(str_of(prepare, "run").unwrap());
    let has = |line: &str| lines.iter().any(|l| l.trim() == line);
    let toolchains: Vec<&String> = tracked
        .iter()
        .filter(|f| *f == "rust-toolchain.toml" || f.ends_with("/rust-toolchain.toml"))
        .collect();
    assert!(toolchains.len() >= 2, "{toolchains:?}");
    for file in &toolchains {
        let install = match file.strip_suffix("/rust-toolchain.toml") {
            Some(dir) => format!("(cd {dir} && rustup toolchain install)"),
            None => "rustup toolchain install".to_string(),
        };
        assert!(has(&install), "{FILE}: `{install}` ({file}) before init");
    }
    assert!(has("rustup component add rust-src"), "{FILE}: {lines:?}");
    for lock in &lockfiles {
        let fetch = match lock.strip_suffix("/Cargo.lock") {
            Some(dir) => format!("(cd {dir} && cargo fetch --locked)"),
            None => "cargo fetch --locked".to_string(),
        };
        assert!(has(&fetch), "{FILE}: `{fetch}` before init");
    }
    let check = job_steps[analyze_at + 1..keep_at]
        .iter()
        .find(|s| {
            rust_only(s) && str_of(s, "run").is_some_and(|r| r.contains("git diff --exit-code"))
        })
        .unwrap_or_else(|| {
            panic!("{FILE}: a Rust step between analyze and the artifact checks the lockfiles")
        });
    let check = str_of(check, "run").unwrap();
    for lock in &lockfiles {
        assert!(
            check.contains(lock.as_str()),
            "{FILE}: the check skips {lock}"
        );
    }

    // Nothing else: the bundle stays, no secret, no token handed over.
    let code: String = text
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    for banned in [
        "hostedtoolcache/CodeQL",
        "secrets.",
        "github.token",
        "GITHUB_TOKEN",
        "token:",
    ] {
        assert!(!code.contains(banned), "{FILE}: `{banned}`");
    }
}

/// Lot 349 (pre-alpha R090): the features no release may carry — the test
/// doors (`test-util`: nn-core's and nn-linux's, an `UnlockToken` minted for
/// a test, `ProcRef::for_test`, a test clock; tokio's `test-util`, its paused
/// clock), the lab's (`test-privileged`, `debug-trigger`), the demos'
/// (`demo-tappa5`, `posture-demo`) and the agent tests' OCSF validator
/// (`schema-check`).
const TEST_ONLY_FEATURES: &[&str] = &[
    "test-util",
    "test-privileged",
    "debug-trigger",
    "demo-tappa5",
    "posture-demo",
    "schema-check",
];

/// Lot 349 (pre-alpha R090): the workspace's features a release may carry
/// (`default`, nn-common's `std`, nn-export's `sinks`; nn-scan's `yara`,
/// whose build fails with the reason). A feature a member declares is in one
/// list or the other.
const RELEASE_FEATURES: &[&str] = &["default", "std", "sinks", "yara"];

/// Lot 349: the packages of `cargo tree --workspace` with `edges` (the
/// features too), and the features each has, as (package, feature).
fn resolved_features(
    edges: &str,
) -> (
    std::collections::BTreeSet<String>,
    std::collections::BTreeSet<(String, String)>,
) {
    let out =
        std::process::Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            .current_dir(repo_root())
            .args([
                "tree",
                "--workspace",
                "--locked",
                "--offline",
                "-e",
                edges,
                "--prefix",
                "none",
                "-f",
                "{p} [{f}]",
            ])
            .output()
            .expect("cargo tree runs");
    assert!(
        out.status.success(),
        "cargo tree failed (build the workspace once, or `cargo fetch --locked`):\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut packages = std::collections::BTreeSet::new();
    let mut found = std::collections::BTreeSet::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let name = line.split_whitespace().next().unwrap_or("").to_string();
        // a feature node: `nn-core feature "test-util"` (then, maybe, why)
        if let Some(rest) = line.split(" feature \"").nth(1) {
            let f = rest.split('"').next().unwrap_or("");
            found.insert((name, f.to_string()));
            continue;
        }
        // a package node: `nn-core v0.0.1 (/…) [a,b]`
        if let (Some(open), Some(close)) = (line.rfind(" ["), line.rfind(']')) {
            packages.insert(name.clone());
            for f in line[open + 2..close].split(',').filter(|f| !f.is_empty()) {
                found.insert((name.clone(), f.to_string()));
            }
        }
    }
    (packages, found)
}

/// Lot 349 (pre-alpha R090, named): the release build's feature set — the
/// exact build release.yml runs (`cargo --locked xtask build --release
/// --locked`, no `--features`: PROC-015 above), which is `cargo build
/// --workspace --release` (xtask's userland build) — enables no test-only
/// feature of any crate. Its graph is the workspace's normal and build
/// edges: a dev-dependency's feature (the agent's tests ask nn-core and
/// nn-linux for `test-util`) is not in it. Adding `features = ["test-util"]`
/// to a normal dependency, a test feature to a default, or a `test` /
/// `debug` / `demo` / `mock` feature of any crate to the release path fails
/// here.
#[test]
fn the_release_build_enables_no_test_feature() {
    let wf = fs::read_to_string(repo_root().join(".github/workflows/release.yml")).unwrap();
    assert!(
        wf.contains("run: cargo --locked xtask build --release --locked"),
        "release.yml: the release build this test resolves is `cargo --locked xtask build \
         --release --locked`"
    );
    let xtask = fs::read_to_string(repo_root().join("xtask/src/main.rs")).unwrap();
    assert!(
        xtask.contains("cmd.current_dir(&root).args([\"build\", \"--workspace\"]);"),
        "xtask's userland build is `cargo build --workspace` (the graph resolved here)"
    );
    let (packages, release) = resolved_features("normal,build,features");
    for krate in [
        "northnarrow-agent",
        "northnarrow-watchdog",
        "nn-core",
        "nn-linux",
        "tokio",
    ] {
        assert!(
            packages.contains(krate),
            "cargo tree's release graph does not list {krate} ({} packages read)",
            packages.len()
        );
    }
    let bad: Vec<String> = release
        .iter()
        .filter(|(_, f)| {
            TEST_ONLY_FEATURES.contains(&f.as_str())
                || ["test", "debug", "demo", "mock", "fake"]
                    .iter()
                    .any(|w| f.to_ascii_lowercase().contains(w))
        })
        .map(|(p, f)| format!("{p}/{f}"))
        .collect();
    assert!(
        bad.is_empty(),
        "the release build (cargo build --workspace --release) enables test-only features: {}",
        bad.join(", ")
    );
    // the mini-hunt: a `--cfg feature="…"` in the release's flags turns a
    // test door on with no feature at all (cargo tree would not see it)
    for rel in [".github/workflows/release.yml", ".cargo/config.toml"] {
        let text = fs::read_to_string(repo_root().join(rel)).unwrap();
        for (i, line) in text.lines().enumerate() {
            let code = line.trim_start();
            assert!(
                code.starts_with('#') || !code.contains("--cfg"),
                "{rel}:{}: a --cfg in the release's flags: {code}",
                i + 1
            );
        }
    }
    // the reader sees one where there is one: the tests' graph has them
    let (_, tests) = resolved_features("normal,build,dev,features");
    for want in [("nn-core", "test-util"), ("nn-linux", "test-util")] {
        assert!(
            tests.iter().any(|(p, f)| p == want.0 && f == want.1),
            "the dev graph should show {}/{}: the parse reads nothing",
            want.0,
            want.1
        );
    }
}

/// Lot 349 (pre-alpha R090, named): every feature a workspace member
/// declares is classified — one a release may carry, or a test-only one —
/// and every test-only feature of a crate the agent links is named by the
/// agent's `--build-features` (`build_info::LAB_FEATURES` for its own,
/// `DEPENDENCY_TEST_FEATURES` for its dependencies'), which release.yml
/// checks to be `none` on the tarball's, the .deb's and the .rpm's binary:
/// a shipped binary built with one is refused before the upload.
#[test]
fn every_feature_is_classified_and_the_shipped_binary_names_its_test_ones() {
    let members = support::members();
    let mut unclassified = Vec::new();
    for m in &members {
        for f in &m.features {
            if !TEST_ONLY_FEATURES.contains(&f.as_str()) && !RELEASE_FEATURES.contains(&f.as_str())
            {
                unclassified.push(format!("{}/{f}", m.name));
            }
        }
    }
    assert!(
        unclassified.is_empty(),
        "classify each feature as release (RELEASE_FEATURES) or test-only (TEST_ONLY_FEATURES): {}",
        unclassified.join(", ")
    );
    let info = fs::read_to_string(repo_root().join("agent/src/build_info.rs")).unwrap();
    let agent = members
        .iter()
        .find(|m| m.name == "northnarrow-agent")
        .expect("the agent");
    let linked: Vec<&str> = agent
        .deps
        .iter()
        .filter(|d| d.kind == "normal" && d.path)
        .map(|d| d.name.as_str())
        .collect();
    // lot 379 (the review of #586, P3-5): every test-only feature of a
    // linked crate, not only `test-util` (a `nn-linux/test-privileged`
    // build without the agent's own feature said `none`), named with the
    // crate's own `cfg!` of it
    let mut unnamed = Vec::new();
    let mut named = 0;
    for m in members.iter().filter(|m| linked.contains(&m.name.as_str())) {
        for f in m
            .features
            .iter()
            .filter(|f| TEST_ONLY_FEATURES.contains(&f.as_str()))
        {
            let krate = m.name.replace('-', "_");
            let konst = f.to_uppercase().replace('-', "_");
            let entry = format!("(\"{}/{f}\", {krate}::{konst}),", m.name);
            let lib = repo_root().join(&m.dir).join("src/lib.rs");
            let defined = fs::read_to_string(&lib)
                .unwrap_or_default()
                .contains(&format!(
                    "pub const {konst}: bool = cfg!(feature = \"{f}\");"
                ));
            if !info.contains(&entry) || !defined {
                unnamed.push(format!("{}/{f}", m.name));
            }
            named += 1;
        }
    }
    assert!(
        unnamed.is_empty(),
        "build_info::DEPENDENCY_TEST_FEATURES must name, with the crate's own `pub const \
         <FEATURE>: bool = cfg!(feature = …)`, {}",
        unnamed.join(", ")
    );
    assert!(named >= 9, "the linked crates' test-only features: {named}");
    assert!(
        info.contains(".chain(DEPENDENCY_TEST_FEATURES)"),
        "build_features() names the dependencies' test features"
    );
}

/// The glibc of each GitHub-hosted image the release may be built on.
const RUNNER_GLIBC: [(&str, &str); 3] = [
    ("ubuntu-22.04", "2.35"),
    ("ubuntu-24.04", "2.39"),
    ("ubuntu-26.04", "2.43"),
];

/// `GLIBC_BASELINE=` of deploy/release/glibc-baseline.sh.
fn glibc_baseline() -> String {
    let script = read(&repo_root().join("deploy/release/glibc-baseline.sh"));
    script
        .lines()
        .find_map(|l| l.strip_prefix("GLIBC_BASELINE="))
        .map(|v| v.trim().to_string())
        .expect("deploy/release/glibc-baseline.sh sets GLIBC_BASELINE=")
}

fn version_key(s: &str) -> Vec<u64> {
    s.split('.').map(|p| p.parse().unwrap()).collect()
}

fn version_le(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> { s.split('.').map(|p| p.parse().unwrap()).collect() };
    parse(a) <= parse(b)
}

/// Lot 365 (an external tester's run on Debian 12): the release was linked
/// on Ubuntu 24.04 (glibc 2.39), so every `nn-admin` on Debian 12 and Ubuntu
/// 22.04 printed `weak version 'GLIBC_2.39' not found`, and an image with a
/// newer glibc could have shipped binaries that do not start there. The
/// package job builds on the image of the oldest supported glibc, and a
/// step checks every shipped ELF file — the tarball's, the .deb's and the
/// .rpm's — against that baseline after a selftest that proves the check
/// refuses a weak need. The packages never ask for a glibc newer than the
/// baseline.
#[test]
fn the_release_is_built_and_checked_on_the_glibc_baseline() {
    let root = repo_root();
    let baseline = glibc_baseline();
    assert_eq!(
        baseline, "2.34",
        "the oldest supported glibc is AlmaLinux/RHEL 9's (2.34), the packages' floor"
    );
    let wf = workflow_yaml(&root.join(".github/workflows/release.yml"));
    let package = jobs(&wf)
        .into_iter()
        .find(|(n, _)| n == "package")
        .map(|(_, j)| j)
        .expect("release.yml has a package job");
    let image = str_of(&package, "runs-on").expect("package: runs-on");
    let glibc = RUNNER_GLIBC
        .iter()
        .find(|(i, _)| *i == image)
        .map(|(_, g)| *g)
        .unwrap_or_else(|| {
            panic!(
                "package runs on `{image}`, not a pinned image of known glibc ({RUNNER_GLIBC:?})"
            )
        });
    // The build image is the OLDEST of the images the release could use
    // (never ubuntu-latest): no image of a lower glibc exists on GitHub, and
    // the check, not the image, holds the needs at the baseline.
    let oldest = RUNNER_GLIBC
        .iter()
        .min_by_key(|(_, g)| version_key(g))
        .map(|(i, _)| *i)
        .unwrap();
    assert_eq!(
        image, oldest,
        "package runs on {image} (glibc {glibc}): the release is built on the oldest image ({oldest})"
    );
    assert!(
        version_le(&baseline, glibc),
        "the baseline {baseline} is above the image's glibc {glibc}: nothing could link"
    );
    let runs: Vec<String> = steps(&package)
        .iter()
        .map(|s| str_of(s, "run").unwrap_or("").to_string())
        .collect();
    let at = |needle: &str| {
        runs.iter()
            .position(|r| r.contains(needle))
            .unwrap_or_else(|| panic!("no package step runs `{needle}`"))
    };
    let check = at("deploy/release/glibc-baseline.sh check \"$tmp/tgz\" \"$tmp/deb\" \"$tmp/rpm\"");
    assert_eq!(
        at("deploy/release/glibc-baseline.sh selftest"),
        check,
        "the selftest runs in the check's step, before it"
    );
    // The glibc step is unconditional: no `if:`, no `continue-on-error`
    // (`if: false` or a swallowed failure would let a release pass without
    // the check; sign requires package's success, publish requires sign).
    let check_step = &steps(&package)[check];
    for key in ["if", "continue-on-error"] {
        assert!(
            check_step.get(key).is_none(),
            "the glibc step must not carry `{key}:` (it runs on every release and its failure fails the job)"
        );
    }
    assert!(
        package.get("continue-on-error").is_none(),
        "the package job must not carry `continue-on-error:`"
    );
    let step = &runs[check];
    assert!(
        step.find("selftest").unwrap() < step.find(" check ").unwrap(),
        "the selftest runs before the check"
    );
    for needle in ["tar -C \"$tmp/tgz\" -xzf", "dpkg-deb -x", "rpm2cpio"] {
        assert!(
            step.contains(needle),
            "the check's step extracts with `{needle}`"
        );
    }
    assert!(
        check > at("deploy/release/mk-packages.sh dist"),
        "the check reads the packages, so it runs after they are built"
    );
    let upload = steps(&package)
        .iter()
        .position(|s| str_of(s, "uses").is_some_and(|u| u.starts_with("actions/upload-artifact@")))
        .expect("package uploads its artefacts");
    assert!(
        check < upload,
        "the check runs before the artefacts are uploaded"
    );
    // The packages' floors never exceed what the build guarantees.
    let pkgs = read(&root.join("deploy/release/mk-packages.sh"));
    for (marker, what) in [
        ("libc6 (>= ", ".deb Depends"),
        ("glibc >= ", ".rpm Requires"),
    ] {
        let floor: String = pkgs
            .split(marker)
            .nth(1)
            .unwrap_or_else(|| panic!("mk-packages.sh: no `{marker}` ({what})"))
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        assert_eq!(
            floor, baseline,
            "the {what} floor {floor} must equal the check's baseline {baseline}: one ceiling"
        );
    }
}

/// Lot 365: the check itself, against binaries built on purpose — a strong
/// and a weak (`Flags: WEAK`, as the release's linker marks Rust's probes)
/// need of GLIBC_2.35 (one above the baseline) and of GLIBC_2.39 refused,
/// GLIBC_2.34 (the baseline) accepted, an undeclared library refused. Runs cc and the toolchain's rust-lld; no network.
#[test]
fn glibc_baseline_check_refuses_a_binary_that_needs_above_2_34() {
    let out = std::process::Command::new("bash")
        .arg(repo_root().join("deploy/release/glibc-baseline.sh"))
        .arg("selftest")
        .output()
        .expect("bash runs");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "glibc-baseline.sh selftest failed:\n{text}"
    );
    for line in [
        "selftest ok    a strong need of GLIBC_2.39 is refused (exit 1)",
        "selftest ok    a weak need of GLIBC_2.39 is refused (exit 1)",
        "selftest ok    a strong need of GLIBC_2.35 is refused (exit 1)",
        "selftest ok    a weak need of GLIBC_2.35 is refused (exit 1)",
        "selftest ok    a need of GLIBC_2.34 is accepted (exit 0)",
        "selftest ok    an undeclared shared library is refused (exit 1)",
        "glibc-baseline: selftest passed",
    ] {
        assert!(text.contains(line), "missing `{line}`:\n{text}");
    }
}

// ---------------------------------------------------------------------------
// Lot 1.8 (the reviews of #610): the export worker's OS generator, and the
// test PKI's private keys.

/// The export worker's production code: nn-export's sources and the
/// worker's life in the agent.
fn export_worker_code() -> Vec<(String, String)> {
    support::product_code(&repo_root())
        .into_iter()
        .filter(|(rel, _)| {
            rel.starts_with("crates/nn-export/src/") || rel == "agent/src/export/worker.rs"
        })
        .collect()
}

/// What the export worker may not draw with: a generator that panics on a
/// failed draw (rand_core's `UnwrapErr`, the agent's `OsRng`), one of
/// userland, or x25519-dalek's own draw (`expect`s getrandom).
const PANICKING_DRAWS: &[&str] = &[
    "UnwrapErr",
    "OsRng",
    "rand::rng(",
    "thread_rng",
    "EphemeralSecret::random(",
    "StaticSecret::random(",
    "ReusableSecret::random(",
];

/// The needles of [`PANICKING_DRAWS`] in `code`, as `path:line: needle`.
fn panicking_draws(rel: &str, code: &str) -> Vec<String> {
    let mut bad = Vec::new();
    for (i, line) in code.lines().enumerate() {
        for n in PANICKING_DRAWS {
            if line.contains(n) {
                bad.push(format!("{rel}:{}: `{n}`", i + 1));
            }
        }
    }
    bad
}

/// Named (lot 1.8, the review of #610): the export worker's key exchange
/// draws its secret from the OS generator through `tls::ephemeral_secret`
/// alone, which turns a failed draw into the handshake's error; no
/// production code of the worker draws with a generator that panics (the
/// release profile aborts the worker on a panic), and none draws a secret
/// another way. The CI of #616: every random of the TLS provider (the
/// hello's too) comes from `tls::Os`, the one draw of getrandom's `SysRng`,
/// which the unit tests fail on any kernel by an injection compiled out of
/// the worker.
#[test]
fn the_export_worker_draws_without_a_panic() {
    let code = export_worker_code();
    assert!(
        code.len() >= 10,
        "{} files of the export worker",
        code.len()
    );
    let bad: Vec<String> = code
        .iter()
        .flat_map(|(rel, c)| panicking_draws(rel, c))
        .collect();
    assert!(
        bad.is_empty(),
        "a draw that panics on a failed getrandom in the export worker (use \
         nn_export::tls::ephemeral_secret's way: a checked draw, its failure an error):\n{}",
        bad.join("\n")
    );
    let draws: Vec<String> = code
        .iter()
        .flat_map(|(rel, c)| {
            c.lines()
                .enumerate()
                .filter(|(_, l)| l.contains("random_from_rng(") || l.contains("from_rng("))
                .map(move |(i, _)| format!("{rel}:{}", i + 1))
        })
        .collect();
    assert_eq!(
        draws.len(),
        1,
        "one secret drawn, in ephemeral_secret: {draws:?}"
    );
    let tls = &code
        .iter()
        .find(|(rel, _)| rel == "crates/nn-export/src/tls.rs")
        .expect("nn-export's TLS client moved: update this test")
        .1;
    let body = |sig: &str| {
        let at = tls
            .find(sig)
            .unwrap_or_else(|| panic!("tls.rs: no `{sig}`"));
        let rest = &tls[at..];
        rest[..support::matching_brace(rest)].to_string()
    };
    let drawer = body("fn ephemeral_secret<");
    assert!(drawer.contains("random_from_rng(&mut draw)"), "{drawer}");
    assert!(
        drawer.contains("if draw.failed")
            && drawer.contains("return Err(rustls::Error::FailedToGetRandomBytes)"),
        "{drawer}"
    );
    let start = body("fn start(&self)");
    assert!(
        start.contains("ephemeral_secret(&mut Os)?"),
        "the X25519 group's start draws through ephemeral_secret, from Os: {start}"
    );
    // the CI of #616: every random of the provider from `Os` (the hello's
    // too), getrandom's `SysRng` drawn there alone, and the unit tests'
    // injection into it compiled out of the worker
    let provider = body("pub fn provider()");
    assert!(
        provider.contains("p.secure_random = &OsRandom;"),
        "the hello's randoms from Os: {provider}"
    );
    let random = body("impl rustls::crypto::SecureRandom for OsRandom");
    assert!(random.contains("Os.try_fill_bytes(bytes)"), "{random}");
    let sys: Vec<String> = code
        .iter()
        .flat_map(|(rel, c)| {
            c.lines()
                .enumerate()
                .filter(|(_, l)| l.contains("SysRng"))
                .map(move |(i, l)| format!("{rel}:{}: {}", i + 1, l.trim()))
        })
        .collect();
    assert!(
        sys.len() == 1 && sys[0].ends_with(": getrandom::SysRng.try_fill_bytes(dst)"),
        "the OS generator drawn in Os alone: {sys:?}"
    );
    assert!(
        !tls.contains("GENERATOR_DOWN"),
        "the tests' injection into Os is #[cfg(test)]"
    );
}

/// The scanner of the export worker's draws catches a planted copy of each
/// pattern, and leaves the checked draw.
#[test]
fn the_draw_scanner_catches_its_patterns() {
    let planted = concat!(
        "let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);\n",
        "let k = SigningKey::generate(&mut OsRng);\n",
        "let n: u64 = rand::rng().random();\n",
        "let s = x25519_dalek::EphemeralSecret::random();\n",
        "let secret = ephemeral_secret(&mut Os)?;\n",
    );
    let found = panicking_draws("x.rs", planted);
    for line in 1..=4 {
        assert!(
            found
                .iter()
                .any(|f| f.starts_with(&format!("x.rs:{line}:"))),
            "line {line}: {found:?}"
        );
    }
    assert!(!found.iter().any(|f| f.starts_with("x.rs:5:")), "{found:?}");
}

/// The test PKI's directory, and the first words of each key's header.
const TEST_PKI: &str = "crates/nn-export/tests/pki/";
const TEST_KEY_HEADER: &str = "TEST-ONLY KEY, NOT A SECRET.";

/// A PEM private key's first line (`-----BEGIN [RSA |EC |OPENSSH |…]PRIVATE
/// KEY-----`, PKCS#8's `ENCRYPTED PRIVATE KEY` too), at the start of a line.
fn begins_a_private_key(line: &str) -> bool {
    let l = line.trim_end();
    l.starts_with("-----BEGIN ") && l.ends_with("PRIVATE KEY-----")
}

/// Named (lot 1.8, the review of #610): the repository's PEM private keys
/// are nn-export's test keys, and nothing else: each tracked file that holds
/// one lies in the test PKI's directory and starts with the header saying it
/// is a test-only key; GitHub's secret scanning skips that directory and no
/// other (`.github/secret_scanning.yml`); `.gitignore` lets keys in there
/// alone.
#[test]
fn private_keys_are_test_keys_out_of_secret_scanning() {
    let root = repo_root();
    let mut keys = Vec::new();
    let mut bad = Vec::new();
    for rel in support::tracked_files() {
        let Ok(text) = fs::read_to_string(root.join(&rel)) else {
            continue;
        };
        if !text.lines().any(begins_a_private_key) {
            continue;
        }
        if !rel.starts_with(TEST_PKI) {
            bad.push(format!("{rel}: a PEM private key outside {TEST_PKI}"));
        } else if !text.starts_with(TEST_KEY_HEADER) {
            bad.push(format!("{rel}: no `{TEST_KEY_HEADER}` header"));
        }
        keys.push(rel);
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    let mut names: Vec<&str> = keys.iter().map(|k| &k[TEST_PKI.len()..]).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        ["ed25519-srv.key", "p384-srv.key", "rsa-srv.key", "srv.key"],
        "the test PKI's keys (README.md there)"
    );
    // the exclusion: that directory, nothing else
    let cfg: support::yaml::Value =
        support::yaml::from_str(&read(&root.join(".github/secret_scanning.yml")))
            .expect(".github/secret_scanning.yml parses");
    let ignored: Vec<&str> = cfg
        .get("paths-ignore")
        .and_then(|v| v.as_sequence())
        .expect("secret_scanning.yml: a `paths-ignore` list")
        .iter()
        .map(|v| v.as_str().expect("a path"))
        .collect();
    assert_eq!(ignored, [format!("{TEST_PKI}**")]);
    assert_eq!(
        cfg.as_mapping().map(|m| m.len()),
        Some(1),
        "secret_scanning.yml: paths-ignore alone"
    );
    // .gitignore ignores keys, and lets them in under the test PKI only
    let gitignore = read(&root.join(".gitignore"));
    let lines: Vec<&str> = gitignore.lines().map(str::trim).collect();
    assert!(lines.contains(&"*.key") && lines.contains(&"*.pem"));
    for l in lines.iter().filter(|l| l.starts_with('!')) {
        if l.ends_with(".key") || l.ends_with(".pem") {
            assert!(l.starts_with(&format!("!{TEST_PKI}")), ".gitignore: {l}");
        }
    }
    // the scanner: a key's first line, not a template's quoted one
    assert!(begins_a_private_key("-----BEGIN PRIVATE KEY-----"));
    assert!(begins_a_private_key(
        "-----BEGIN OPENSSH PRIVATE KEY-----\r"
    ));
    assert!(begins_a_private_key(
        "-----BEGIN ENCRYPTED PRIVATE KEY-----"
    ));
    assert!(!begins_a_private_key(
        "  \"private_key\": \"-----BEGIN PRIVATE KEY-----\\n{{body}}\\n-----END PRIVATE KEY-----\\n\","
    ));
    assert!(!begins_a_private_key("-----BEGIN CERTIFICATE-----"));
}
