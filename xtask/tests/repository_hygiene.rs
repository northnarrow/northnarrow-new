//! Developer-tooling hygiene of the repository itself (external audit
//! WDG-R10 NN-AUD-376, WDG-R11 NN-AUD-377). The tests read committed files
//! and run nothing.
//!
//! - No developer's home directory in the sources, scripts and
//!   configuration: `ade_smoke` defaulted its model to one, and three test
//!   fixtures carried the same home. Fixtures use the neutral names of
//!   [`FIXTURE_HOMES`].
//! - No `cargo` under `sudo` in the developer examples or the operator
//!   guides: `verify_chainlog` documented `sudo cargo run`, which compiles,
//!   and runs the build scripts of the whole dependency graph, as root.
//!   The privileged e2e suites run their `cargo test` as root on purpose,
//!   on lab VMs only (`docs/integration-test-runbook.md`); they are outside
//!   these two trees.

use std::fs;
use std::path::{Path, PathBuf};

/// The home directories test fixtures may name. A new fixture takes one of
/// these; add a name here only if it is nobody's real account.
const FIXTURE_HOMES: &[&str] = &[
    "a", "al", "alice", "b", "bob", "carol", "dave", "dev", "eve", "mallory", "nn", "u", "user",
];

/// What the home-directory scan reads: sources, scripts and configuration.
/// Markdown is left out (the design notes and the audit tracker quote
/// historical paths), and so are the build outputs and the vendored crate.
const SCANNED_EXTENSIONS: &[&str] = &[
    ".rs", ".toml", ".sh", ".yml", ".yaml", ".service", ".conf", ".tmpl",
];
const SKIPPED: &[&str] = &[
    ".git",
    "target",
    "vendor",
    "agent-ebpf/target",
    "fuzz/target",
    "fuzz/corpus",
    "fuzz/artifacts",
];

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
            let r = rel(&path);
            if skip
                .iter()
                .any(|s| r == *s || r.starts_with(&format!("{s}/")))
            {
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

/// The account names of the `/home/<name>` and `/Users/<name>` paths in
/// `line` that are not fixture names. `/home/` alone, `/home/$USER`,
/// `/home/.` and `/home//x` name no account.
fn personal_homes(line: &str) -> Vec<String> {
    let mut found = Vec::new();
    for prefix in ["/home/", "/Users/"] {
        let mut rest = line;
        while let Some(at) = rest.find(prefix) {
            let after = &rest[at + prefix.len()..];
            let name: String = after
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
                .collect();
            if !name.is_empty()
                && !name.chars().all(|c| c == '.')
                && !FIXTURE_HOMES.contains(&name.as_str())
            {
                found.push(name);
            }
            rest = after;
        }
    }
    found
}

/// The options of `sudo` and of `env` that take the next word as their
/// value (`sudo -u root`, `env -u HOME`).
const SUDO_VALUE_OPTIONS: &[&str] = &[
    "-u", "-g", "-C", "-D", "-p", "-r", "-t", "-T", "-U", "-R", "--user", "--group", "--chdir",
    "--prompt",
];
const ENV_VALUE_OPTIONS: &[&str] = &["-u", "-C", "-S", "--unset", "--chdir", "--split-string"];

/// Skips, from `j`, the words that are options (and their values) or, with
/// `assignments`, `NAME=value` words.
fn skip_options(words: &[&str], mut j: usize, valued: &[&str], assignments: bool) -> usize {
    while j < words.len() {
        let w = words[j];
        if valued.contains(&w) {
            j += 2;
        } else if w.starts_with('-') || (assignments && w.contains('=')) {
            j += 1;
        } else {
            break;
        }
    }
    j
}

/// Whether `line` holds a `cargo` command run through `sudo`: `sudo`, its
/// options, optionally `env` with its options and assignments, then
/// `cargo`. Backticks and quotes around the words are ignored, so prose
/// that names sudo ("sudo sets HOME") is not a command.
fn runs_cargo_under_sudo(line: &str) -> bool {
    let words: Vec<&str> = line
        .split_whitespace()
        .map(|w| w.trim_matches(|c| matches!(c, '`' | '"' | '\'' | '(' | ')' | '$')))
        .collect();
    for (i, w) in words.iter().enumerate() {
        if *w != "sudo" {
            continue;
        }
        let mut j = skip_options(&words, i + 1, SUDO_VALUE_OPTIONS, false);
        if words.get(j) == Some(&"env") {
            j = skip_options(&words, j + 1, ENV_VALUE_OPTIONS, true);
        }
        if words.get(j) == Some(&"cargo") {
            return true;
        }
    }
    false
}

#[test]
fn no_developer_home_in_sources_scripts_or_configuration() {
    let root = repo_root();
    let files = files_under(&root, SCANNED_EXTENSIONS, SKIPPED);
    assert!(
        files
            .iter()
            .any(|f| rel(f) == "agent/examples/ade_smoke.rs"),
        "the scan must reach the examples"
    );
    let mut bad = Vec::new();
    for file in &files {
        let Ok(text) = fs::read_to_string(file) else {
            continue; // not UTF-8: not a source file
        };
        for (n, line) in text.lines().enumerate() {
            for name in personal_homes(line) {
                bad.push(format!("{}:{}: home of `{name}`", rel(file), n + 1));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "a developer's home directory in the repository (a default path or a fixture); \
         defaults go under /var/lib/northnarrow or come from the environment, fixtures \
         use one of {FIXTURE_HOMES:?}:\n{}",
        bad.join("\n")
    );
}

#[test]
fn no_cargo_under_sudo_in_examples_or_operator_guides() {
    let root = repo_root();
    let mut files = files_under(&root.join("agent/examples"), &[".rs"], &[]);
    let examples = files.len();
    files.extend(files_under(&root.join("docs/operator"), &[".md"], &[]));
    assert!(
        examples >= 5 && files.len() > examples,
        "the scan must reach the examples and the operator guides: {files:?}"
    );
    let mut bad = Vec::new();
    for file in &files {
        let text = fs::read_to_string(file).unwrap_or_else(|e| panic!("{}: {e}", rel(file)));
        for (n, line) in text.lines().enumerate() {
            if runs_cargo_under_sudo(line) {
                bad.push(format!("{}:{}: {}", rel(file), n + 1, line.trim()));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "cargo run as root: build as yourself and run the built binary under sudo \
         (`sudo ./target/release/...`):\n{}",
        bad.join("\n")
    );
}

/// The two scanners themselves: what they must flag and what they must not.
#[test]
fn the_hygiene_scanners_flag_what_they_should() {
    // Built at run time so that this file holds no such path itself.
    let home = |rest: &str| format!("/{}/{rest}", "home");
    assert_eq!(
        personal_homes(&format!("\"{}\".into()", home("jdoe/models/x.gguf"))),
        ["jdoe"]
    );
    assert_eq!(
        personal_homes(&format!("cd /{}/jdoe/src", "Users")),
        ["jdoe"]
    );
    assert_eq!(
        personal_homes(&format!("{} {}", home("jdoe.smith/a"), home("j-doe/b"))),
        ["jdoe.smith", "j-doe"]
    );
    for clean in [
        "/home/alice/.npm-global/lib/node_modules/left-pad/index.js",
        "/home/u/Documents/a /home/nn/.local/share/containers",
        "lowerdir=/home/, /home//bob, /home/./x, /home/.../y",
        "\"/home/$USER/.cache\"",
        "/var/lib/northnarrow/models/foundation-sec-8b-reasoning-q4_k_m.gguf",
    ] {
        assert!(personal_homes(clean).is_empty(), "{clean}");
    }

    for command in [
        "//!   sudo cargo run -p northnarrow-agent --example verify_chainlog -- \\",
        "sudo -E cargo test --release",
        "`sudo -E env \"PATH=$PATH\" cargo test --release`",
        "sudo env -u HOME RUSTUP_HOME=/x cargo build",
        "sudo -u root -E cargo run --example ade_smoke",
    ] {
        assert!(runs_cargo_under_sudo(command), "{command}");
    }
    for clean in [
        "cargo build --release -p northnarrow-agent --example verify_chainlog",
        "sudo ./target/release/examples/verify_chainlog \\",
        "- RHEL-family sudo sets `HOME=/root` (`always_set_home`), so the root `cargo test`",
        "sudo systemctl restart northnarrow-agent  # then cargo nothing",
    ] {
        assert!(!runs_cargo_under_sudo(clean), "{clean}");
    }
}
