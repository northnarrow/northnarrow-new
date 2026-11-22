//! Lot 385 (the external tester's F9b-1): the `nn-admin` commands the README
//! and the operator guides give are commands `nn-admin` takes. The tester's
//! guide (§7), the README's Quickstart and `INSTALL_UPGRADE_UNINSTALL.md`
//! gave `sudo nn-admin audit verify`, which exited 2 ("required arguments
//! were not provided: --from").
//!
//! The truth is the binary's own help: every subcommand's `--help` in the
//! golden nn-admin matrix (`agent/tests/golden/nn-admin/expected/help.txt`,
//! which `cargo xtask golden` checks against the binary). Each command of
//! the documents' code blocks must name a command of the matrix that has no
//! subcommand left to name, give each option its usage requires, use only
//! options that command has, give a value to an option that takes one, and
//! give the positionals its usage requires.

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use support::repo_root;

const HELP: &str = "agent/tests/golden/nn-admin/expected/help.txt";

/// One command of the help matrix.
#[derive(Debug, Default)]
struct Command {
    /// It names subcommands (a `Commands:` section).
    parent: bool,
    /// The options its usage requires (`--key`), outside `[…]`.
    required: BTreeSet<String>,
    /// How many positionals its usage requires (`<PID>` outside `[…]`, not
    /// an option's value).
    positionals: usize,
    /// Its options (long and short), and whether each takes a value.
    options: BTreeMap<String, bool>,
}

/// The matrix's commands, by their words after `nn-admin`.
fn commands() -> BTreeMap<Vec<String>, Command> {
    let text = fs::read_to_string(repo_root().join(HELP)).expect("the help matrix");
    let mut out = BTreeMap::new();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        let Some(words) = line
            .strip_prefix("$ nn-admin ")
            .and_then(|r| r.strip_suffix(" --help"))
        else {
            continue;
        };
        let path: Vec<String> = words.split_whitespace().map(str::to_string).collect();
        let mut c = Command::default();
        let mut section = "";
        while let Some(l) = lines.next_if(|l| !l.starts_with("### ")) {
            let Some(body) = l.strip_prefix("| ").or_else(|| (l == "|").then_some("")) else {
                continue;
            };
            if let Some(usage) = body.strip_prefix("Usage: nn-admin ") {
                let toks: Vec<&str> = usage.split_whitespace().skip(path.len()).collect();
                let mut depth = 0i32;
                let mut i = 0;
                while i < toks.len() {
                    let t = toks[i];
                    let opens = t.matches('[').count() as i32;
                    let inside = depth + opens > 0;
                    let bare = t.trim_matches(|c| c == '[' || c == ']' || c == '.');
                    if !inside && bare.starts_with("--") {
                        c.required.insert(bare.to_string());
                        if toks.get(i + 1).is_some_and(|n| n.starts_with('<')) {
                            i += 1;
                        }
                    } else if !inside && bare.starts_with('<') && bare != "<COMMAND>" {
                        c.positionals += 1;
                    }
                    depth += opens - t.matches(']').count() as i32;
                    i += 1;
                }
                continue;
            }
            match body.trim_end() {
                "Commands:" => {
                    c.parent = true;
                    section = "commands";
                    continue;
                }
                "Options:" | "Arguments:" => {
                    section = "options";
                    continue;
                }
                _ => {}
            }
            if section == "options" {
                let t = body.trim_start();
                if t.starts_with('-') {
                    let words: Vec<&str> = t.split_whitespace().collect();
                    let mut takes = false;
                    let mut names = Vec::new();
                    for w in &words {
                        let w = w.trim_end_matches(',');
                        if w.starts_with('-') {
                            names.push(w.to_string());
                        } else if w.starts_with('<') {
                            takes = true;
                            break;
                        } else {
                            break;
                        }
                    }
                    for n in names {
                        c.options.insert(n, takes);
                    }
                }
            }
        }
        out.insert(path, c);
    }
    out
}

/// The README and every operator guide (what a release ships).
fn documents() -> Vec<PathBuf> {
    let mut docs = vec![repo_root().join("README.md")];
    let mut guides: Vec<PathBuf> = fs::read_dir(repo_root().join("docs/operator"))
        .expect("docs/operator")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "md"))
        .collect();
    guides.sort();
    docs.extend(guides);
    docs
}

/// The words of a shell command line, quotes removed, up to its end: a
/// comment, a pipe, a redirection (its descriptor too), a list operator or
/// a group's close. A `<placeholder>` (spaces allowed) is one word, an
/// optional `[...]` is read as given.
fn shell_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), c) => cur.push(c),
            (None, '\'' | '"') => quote = Some(c),
            (None, '<') => {
                for c in chars.by_ref() {
                    if c == '>' {
                        break;
                    }
                }
                cur.push_str("PLACEHOLDER");
            }
            (None, '[' | ']') => {}
            (None, '#') if cur.is_empty() => break,
            (None, '>') => {
                if cur.chars().all(|c| c.is_ascii_digit()) {
                    cur.clear();
                }
                break;
            }
            (None, '|' | ';' | '&' | '}') => break,
            (None, c) if c.is_whitespace() => {
                if !cur.is_empty() {
                    words.push(std::mem::take(&mut cur));
                }
            }
            (None, c) => cur.push(c),
        }
    }
    if !cur.is_empty() {
        words.push(cur);
    }
    words
}

/// Every `nn-admin` command line in the fenced blocks of `text` (its words
/// after `nn-admin`), with its line number: the line, past a prompt,
/// `sudo`, a group's `{` or a unit's `ExecStart=`, starts with `nn-admin`
/// (prose quoting a command in a sample output does not); a line ending in
/// `\` goes on.
fn documented(text: &str) -> Vec<(usize, Vec<String>)> {
    let mut out = Vec::new();
    let mut fenced = false;
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim();
        i += 1;
        if line.starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if !fenced {
            continue;
        }
        let mut rest = line;
        for prefix in ["$ ", "{ ", "ExecStart=", "sudo -n ", "sudo "] {
            rest = rest.strip_prefix(prefix).unwrap_or(rest).trim_start();
        }
        let rest = rest
            .strip_prefix("/usr/local/bin/")
            .or_else(|| rest.strip_prefix("/usr/bin/"))
            .unwrap_or(rest);
        let Some(args) = rest.strip_prefix("nn-admin ") else {
            continue;
        };
        let at = i;
        let mut joined = args.to_string();
        while joined.ends_with('\\') && i < lines.len() {
            joined.pop();
            joined.push(' ');
            joined.push_str(lines[i].trim());
            i += 1;
        }
        out.push((at, shell_words(&joined)));
    }
    out
}

/// What is wrong with the command `words` against the matrix, if anything.
fn problem(cmds: &BTreeMap<Vec<String>, Command>, words: &[String]) -> Option<String> {
    if words
        .iter()
        .any(|w| w == "--version" || w == "--help" || w == "-h")
    {
        return None;
    }
    let mut n = 0;
    while n < words.len() && cmds.contains_key(&words[..=n].to_vec()) {
        n += 1;
    }
    if n == 0 {
        return Some(format!(
            "no command `{}`",
            words.first().cloned().unwrap_or_default()
        ));
    }
    let path = &words[..n];
    let c = &cmds[&path.to_vec()];
    if c.parent {
        return Some(format!("`{}` names a group, not a command", path.join(" ")));
    }
    let mut given = BTreeSet::new();
    let mut positionals = 0;
    let mut i = n;
    while i < words.len() {
        let w = &words[i];
        if w.starts_with('-') && w.len() > 1 {
            let (name, inline) = match w.split_once('=') {
                Some((k, _)) => (k.to_string(), true),
                None => (w.clone(), false),
            };
            let Some(&takes) = c.options.get(&name) else {
                return Some(format!("`{}` has no option `{name}`", path.join(" ")));
            };
            if takes && !inline {
                if i + 1 >= words.len() {
                    return Some(format!("`{name}` without its value"));
                }
                i += 1;
            }
            given.insert(name);
        } else {
            positionals += 1;
        }
        i += 1;
    }
    if let Some(missing) = c.required.iter().find(|r| !given.contains(*r)) {
        return Some(format!("`{}` requires `{missing}`", path.join(" ")));
    }
    (positionals < c.positionals).then(|| {
        format!(
            "`{}` requires {} positional(s), {positionals} given",
            path.join(" "),
            c.positionals
        )
    })
}

/// Every `nn-admin` command the README and the operator guides give is one
/// `nn-admin` takes, by its own help.
#[test]
fn every_documented_nn_admin_command_is_one_nn_admin_takes() {
    let cmds = commands();
    assert!(cmds.len() >= 60, "only {} commands in {HELP}", cmds.len());
    let mut checked = 0;
    let mut wrong = Vec::new();
    for doc in documents() {
        let text = fs::read_to_string(&doc).expect("a document");
        let name = doc
            .strip_prefix(repo_root())
            .unwrap_or(&doc)
            .display()
            .to_string();
        for (line, words) in documented(&text) {
            checked += 1;
            if let Some(p) = problem(&cmds, &words) {
                wrong.push(format!(
                    "{name}:{line}: `nn-admin {}`: {p}",
                    words.join(" ")
                ));
            }
        }
    }
    assert!(checked >= 40, "only {checked} documented commands found");
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The checker reads what it must (a prompt, `sudo`, a placeholder with
/// spaces, a continued line, a command's end; prose skipped) and refuses
/// each kind of wrong command.
#[test]
fn the_checker_reads_commands_and_refuses_wrong_ones() {
    let text = "x\n```sh\nsudo nn-admin audit verify          # the log\n\
                nn-admin status --key <config-manage key> > \"$d/s\" 2>&1\n\
                nn-admin detections --key \"$KEY\" --since \"$s\" \\\n  | jq .\n```\n\
                ```\nrecords: 9 — `nn-admin detections` lists them\n```\n";
    let w = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    assert_eq!(
        documented(text),
        vec![
            (3, w(&["audit", "verify"])),
            (4, w(&["status", "--key", "PLACEHOLDER"])),
            (5, w(&["detections", "--key", "$KEY", "--since", "$s"])),
        ]
    );
    let cmds = commands();
    let say = |s: &[&str]| problem(&cmds, &w(s));
    assert_eq!(say(&["audit", "verify"]), None);
    assert_eq!(say(&["detections", "--key", "k", "--limit", "20"]), None);
    assert!(say(&["detections", "--limit", "20"])
        .unwrap()
        .contains("requires `--key`"));
    assert!(say(&["detections", "--key"])
        .unwrap()
        .contains("without its value"));
    assert!(say(&["audit", "verify", "--form", "x"])
        .unwrap()
        .contains("no option"));
    assert!(say(&["audit", "verfy"]).unwrap().contains("names a group"));
    assert!(say(&["nosuch"]).unwrap().contains("no command"));
    // a usage's required option, as the matrix gave it before lot 385
    let mut old = BTreeMap::new();
    old.insert(
        w(&["audit"]),
        Command {
            parent: true,
            ..Command::default()
        },
    );
    old.insert(
        w(&["audit", "verify"]),
        Command {
            required: ["--from".to_string()].into(),
            options: [("--from".to_string(), true)].into(),
            ..Command::default()
        },
    );
    assert!(problem(&old, &w(&["audit", "verify"]))
        .unwrap()
        .contains("requires `--from`"));
}
