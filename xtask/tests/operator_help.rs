//! Lot 354 (pre-alpha, the operator's help, the audit's T7): what an
//! operator reads when they ask for help speaks their language. The help of
//! `nn-admin` (every case of the generated help matrix, which `cargo xtask
//! golden` checks against the binary), of `install.sh` and of
//! `uninstall.sh` names no lot, review, audit finding, design section or
//! development stage; every option the scripts accept is in their help; and
//! the scripts print no colour (so `NO_COLOR` holds for them; nn-admin's
//! colours go through one `NO_COLOR`-aware helper, its own unit test).

use std::fs;
use std::process::Command;

mod support;

use support::repo_root;

fn read(rel: &str) -> String {
    let path = repo_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Words of the project's history that mean nothing to an operator.
const JARGON: [&str; 17] = [
    "Tappa",
    "lab PR",
    "Lab PR",
    "external audit",
    "External audit",
    "NN-AUD-",
    "BUG-",
    "Role::",
    "R12",
    "design §",
    "review of #",
    "Review #",
    "NB:",
    "V1.",
    " V1 ",
    "lock-in",
    // a rustdoc link: a doc comment written for the code, shown as help
    "[`",
];

/// The internal reference `line` makes, if any: a word of [`JARGON`], a
/// lot number, a pull request number, an audit finding's id (`ASK-009`,
/// not a rule id such as `NN-L-FIM-009`), a design question (`Q6`) or a
/// section sign that follows no operator guide.
fn jargon(line: &str) -> Option<String> {
    if let Some(w) = JARGON.iter().find(|w| line.contains(*w)) {
        return Some((*w).to_string());
    }
    let b = line.as_bytes();
    for (i, w) in line.char_indices() {
        let rest = &line[i..];
        let digit_after = |n: usize| b.get(i + n).is_some_and(u8::is_ascii_digit);
        if (rest.starts_with("lot ") || rest.starts_with("Lot ")) && digit_after(4) {
            return Some(rest.chars().take(8).collect());
        }
        if w == '#' && (1..=3).all(digit_after) {
            return Some(rest.chars().take(5).collect());
        }
        if w == 'Q'
            && digit_after(1)
            && (i == 0 || !b[i - 1].is_ascii_alphanumeric())
            && !b.get(i + 2).is_some_and(u8::is_ascii_alphanumeric)
        {
            return Some(rest.chars().take(2).collect());
        }
        if w == '§' && !line[..i].trim_end().ends_with(".md") {
            return Some(rest.chars().take(6).collect());
        }
        // an audit finding: 3 or 4 capitals, '-', 3 digits, not a rule id
        if w.is_ascii_uppercase()
            && (i == 0 || !b[i - 1].is_ascii_alphanumeric() && b[i - 1] != b'-')
        {
            let caps = rest.bytes().take_while(u8::is_ascii_uppercase).count();
            if (3..=4).contains(&caps)
                && b.get(i + caps) == Some(&b'-')
                && (1..=3).all(|n| digit_after(caps + n))
                && !digit_after(caps + 4)
                && !rest.starts_with("SHA-")
            {
                return Some(rest.chars().take(caps + 4).collect());
            }
        }
    }
    None
}

fn jargon_lines(what: &str, text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| jargon(l).map(|j| format!("{what}: `{j}` in: {}", l.trim())))
        .collect()
}

/// The text of every case of nn-admin's generated help matrix.
fn nn_admin_help() -> String {
    read("agent/tests/golden/nn-admin/expected/help.txt")
        .lines()
        .filter_map(|l| l.strip_prefix("| "))
        .collect::<Vec<_>>()
        .join("\n")
}

fn script_help(script: &str) -> String {
    let out = Command::new("bash")
        .arg(repo_root().join(script))
        .arg("--help")
        .env("NO_COLOR", "1")
        .output()
        .expect("bash runs");
    assert!(out.status.success(), "{script} --help: {out:?}");
    String::from_utf8(out.stdout).expect("utf-8") + &String::from_utf8_lossy(&out.stderr)
}

#[test]
fn the_help_speaks_the_operator_s_language() {
    let mut problems = jargon_lines("nn-admin --help", &nn_admin_help());
    for script in ["deploy/install.sh", "deploy/uninstall.sh"] {
        problems.extend(jargon_lines(script, &script_help(script)));
    }
    problems.sort();
    problems.dedup();
    assert!(
        problems.is_empty(),
        "internal references in the operator's help:\n  {}",
        problems.join("\n  ")
    );
}

/// The options a script's argument loop accepts (`--name)` and
/// `--a|--b)` cases, `-y|--yes)` included).
fn accepted_flags(script: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in read(script).lines() {
        let l = line.trim_start();
        if !l.starts_with('-') {
            continue;
        }
        let Some(pat) = l.split(')').next() else {
            continue;
        };
        if pat.contains(' ') || pat.contains('*') || pat.contains('"') {
            continue;
        }
        for flag in pat.split('|') {
            if flag.starts_with('-') && flag.len() > 1 && flag != "-h" && flag != "--help" {
                out.push(flag.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

#[test]
fn every_option_of_the_scripts_is_in_their_help() {
    for script in ["deploy/install.sh", "deploy/uninstall.sh"] {
        let flags = accepted_flags(script);
        assert!(flags.len() >= 4, "{script}: {flags:?}");
        let help = script_help(script);
        let missing: Vec<&String> = flags
            .iter()
            .filter(|f| {
                !help
                    .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
                    .any(|w| w == f.as_str())
            })
            .collect();
        assert!(
            missing.is_empty(),
            "{script} --help does not name {missing:?}"
        );
    }
}

/// The scripts an operator runs write no ANSI colour, so nothing they say
/// is carried by a colour and `NO_COLOR` holds for them as it is.
#[test]
fn the_scripts_print_no_colour() {
    for script in ["deploy/install.sh", "deploy/uninstall.sh"] {
        let text = read(script);
        for (n, line) in text.lines().enumerate() {
            for esc in [
                "\\033[",
                "\\e[",
                "\\x1b[",
                "\\u001b[",
                "tput setaf",
                "tput bold",
            ] {
                assert!(
                    !line.contains(esc),
                    "{script}:{}: prints a colour ({esc}): {line}",
                    n + 1
                );
            }
        }
        assert!(!script_help(script).contains('\u{1b}'), "{script} --help");
    }
}

#[test]
fn the_jargon_checker_sees_each_kind() {
    for (line, hit) in [
        ("Tappa 9.0.b — read the last N", true),
        ("Lab PR 218: this boot's manifest", true),
        ("the lot 341 profile", true),
        ("since #553", true),
        ("per §13 Q6", true),
        ("(external audit ASK-009)", true),
        ("lock-in", true),
        (
            "through [`northnarrow_agent::audit::verify_chain_file`]",
            true,
        ),
        ("FIM-009 self-upgrade", true),
        ("records NN-L-FIM-009 and NN-L-CANARY-002", false),
        ("docs/operator/COMBAT_RECOVERY.md §1.1 adds one", false),
        ("R018_KernelModuleLoad, exit 78", false),
        ("a beat every 30 s; JA3/JA4, SHA-256", false),
        ("QUIC and DoT", false),
    ] {
        assert_eq!(jargon(line).is_some(), hit, "{line}: {:?}", jargon(line));
    }
    assert_eq!(
        accepted_flags("deploy/uninstall.sh")
            .iter()
            .filter(|f| *f == "-y" || *f == "--yes")
            .count(),
        2
    );
}
