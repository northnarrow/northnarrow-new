//! Supply-chain hygiene of the repository itself: what the CI runs, how
//! releases are verified, what the default build targets, and which RustSEC
//! advisories are accepted. External audit SUP-001, SUP-002, SUP-004,
//! SUP-005, SUP-006, SUP-007 to SUP-012, SUP-015, SUP-016, SUP-017, SUP-018,
//! SUP-022, SUP-023 and DEP-008. The tests read committed files; three run a local tool and
//! none touches the network: `prune_script_fails_closed` runs the CI prune
//! script under bash with a stub `cargo`, `advisory_exceptions_expire_in_ci`
//! runs the CI expiry check under bash with a fixed date, and
//! `rust_version_covers_every_locked_dependency` runs `cargo metadata
//! --locked --offline` (the crates a workspace build downloads are enough).

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
/// and its dependents' code, so a bump that moves it (tantivy taking
/// another lru) reopens the entry here instead of leaving an ignore that
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
        let date = |name: &str| {
            field(name).and_then(|d| chrono::NaiveDate::parse_from_str(d, "%Y-%m-%d").ok())
        };
        match (date("Recorded"), date("Expires")) {
            (Some(from), Some(until)) => {
                let days = (until - from).num_days();
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
    let dates = |name: &str| -> Vec<chrono::NaiveDate> {
        entries
            .iter()
            .filter_map(|e| e.fields.iter().find(|(k, _)| k == name))
            .filter_map(|(_, v)| chrono::NaiveDate::parse_from_str(v, "%Y-%m-%d").ok())
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
        let after = last.succ_opt().unwrap();
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
        ("valid", ok_body.as_str(), "2026-12-31", true, "1 exception(s)"),
        ("last-day", ok_body.as_str(), "2027-01-20", true, "1 exception(s)"),
        ("expired", ok_body.as_str(), "2027-01-21", false, "expired on 2027-01-20"),
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
        ("empty", "[advisories]\nignore = []\n", "2026-12-31", true, "0 exception(s)"),
        ("none", "[output]\nquiet = false\n", "2026-12-31", true, "0 exception(s)"),
    ] {
        let (ok, text) = run(&fixture(case, body), today);
        assert_eq!(ok, want_ok, "{case}: {text}");
        assert!(text.contains(needle), "{case}: `{needle}` not in: {text}");
    }
    let (ok, text) = run(&base.join("missing.toml"), "2026-12-31");
    assert!(!ok && text.contains("not found"), "missing file: {text}");
}

/// SUP-008: the lru exception rests partly on the release profile aborting
/// on a panic (no unwinding, so no `catch_unwind` can observe the half-done
/// `pop()`). The shipped profile, and every profile built from it, keeps
/// `panic = "abort"`.
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
        // the kernel interface, /proc and the BTF/ELF parsing
        "libc",
        "nix",
        "aya",
        "aya-obj",
        "object",
        "procfs",
        "procfs-core",
        // the model and the knowledge base, and what they map from disk
        "tantivy",
        "candle-core",
        "tokenizers",
        "safetensors",
        "memmap2",
        // the crates of the recorded exceptions (also taken from audit.toml)
        "lru",
        "paste",
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
    assert!(out.len() >= 13, "fuzz/Cargo.toml: {} targets", out.len());
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
    for krate in ["agent", "common", "watchdog", "cli", "ebpf-guard", "xtask"] {
        for file in files_under(&root.join(krate).join("src"), &[".rs"], &[]) {
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
