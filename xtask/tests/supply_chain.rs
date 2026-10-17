//! Supply-chain hygiene of the repository itself: what the CI runs, how
//! releases are verified, and what the default build targets. External
//! audit SUP-001, SUP-002, SUP-004, SUP-005, SUP-006, SUP-012, SUP-015,
//! SUP-016, SUP-017, SUP-022 and DEP-008. The tests read committed files;
//! two run a local tool and none touches the network:
//! `prune_script_fails_closed` runs the CI prune script under bash with a
//! stub `cargo`, and `rust_version_covers_every_locked_dependency` runs
//! `cargo metadata --locked --offline` (the crates a workspace build
//! downloads are enough).

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

fn workflow_yaml(file: &Path) -> serde_yaml_ng::Value {
    serde_yaml_ng::from_str(&read(file)).unwrap_or_else(|e| panic!("{}: {e}", rel(file)))
}

/// The jobs of a workflow, by name.
fn jobs(wf: &serde_yaml_ng::Value) -> Vec<(String, serde_yaml_ng::Value)> {
    wf.get("jobs")
        .and_then(|j| j.as_mapping())
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.as_str().unwrap_or("?").to_string(), v.clone()))
                .collect()
        })
        .unwrap_or_default()
}

fn steps(job: &serde_yaml_ng::Value) -> Vec<serde_yaml_ng::Value> {
    job.get("steps")
        .and_then(|s| s.as_sequence())
        .cloned()
        .unwrap_or_default()
}

fn str_of<'a>(v: &'a serde_yaml_ng::Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(|x| x.as_str())
}

/// SUP-004: without a `permissions:` block the token gets the repository's
/// default, which can be read/write. Every workflow starts read-only; a
/// job asks for more only where it publishes (release.yml's `sign`).
#[test]
fn every_workflow_token_is_read_only_unless_it_publishes() {
    const WRITE_ALLOWED: [(&str, &str, &str); 3] = [
        (".github/workflows/release.yml", "sign", "contents"),
        (".github/workflows/release.yml", "sign", "id-token"),
        (".github/workflows/release.yml", "sign", "attestations"),
    ];
    let mut bad = Vec::new();
    for file in workflow_files() {
        let name = rel(&file);
        let wf = workflow_yaml(&file);
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
        for (job, body) in jobs(&wf) {
            let Some(perms) = body.get("permissions") else {
                continue;
            };
            let Some(m) = perms.as_mapping() else {
                // `write-all` / `read-all`
                bad.push(format!("{name}: job {job}: permissions {perms:?}"));
                continue;
            };
            for (scope, level) in m {
                let scope = scope.as_str().unwrap_or("?");
                if level.as_str() == Some("write")
                    && !WRITE_ALLOWED
                        .iter()
                        .any(|(f, j, s)| *f == name && *j == job && *s == scope)
                {
                    bad.push(format!("{name}: job {job}: {scope}: write"));
                }
            }
        }
    }
    assert!(
        bad.is_empty(),
        "workflow tokens must be read-only (write only where release.yml publishes):\n{}",
        bad.join("\n")
    );
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
/// hash from the end of the job's own key.
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
                let own = key.rfind("${{ hashFiles(").map(|i| &key[..i]);
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

    let dependabot: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(&read(&root.join(".github/dependabot.yml"))).unwrap();
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
/// PATH.
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
        for d in [
            "debug/.fingerprint/northnarrow-agent-0123",
            "debug/.fingerprint/serde-4567",
        ] {
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
        assert!(target
            .join("debug/.fingerprint/northnarrow-agent-0123")
            .exists());
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
}

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
