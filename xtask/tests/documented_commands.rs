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
//!
//! Lot 1.7b (stage S1, item F12; the review of #593, finding 4): a line is
//! read as the shell reads it — each simple command of it (after `&&`,
//! `||`, `;`, `|`, inside `$(…)`), past `sudo` and its options, variables,
//! `env`, `if`, `timeout`, `watch` — and the prose's code spans are read
//! too: one that starts with `sudo` or a prompt is checked as a command, any
//! other as a name (a command or a group nn-admin has, and its options).
//! The reader before it (kept in [`lexical`] only to show it) missed each
//! shape planted in `the_lexical_bypasses_are_caught`. The truth itself is
//! checked against the code: the commands nn-admin's clap definitions make
//! (derive and builder forms, read as Rust) are the matrix's.

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use support::ast;
use support::repo_root;
use syn::visit::Visit;

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
                    // lot 2.3b: a bare `--` (`window-run -- <COMMAND>`) ends
                    // the options, it is none
                    if !inside && bare.starts_with("--") && bare.len() > 2 {
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

/// Lot 1.7b (the review of #593, finding 4): the simple commands of a shell
/// line — cut at `&&`, `||`, `;`, `|`, `&`, `(`, `)`, `{`, `}` outside
/// single quotes; a command substitution `$(…)` (in double quotes too) is a
/// command of its own, and a word (`SUBST`) of the command around it.
fn simple_commands(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut outer: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut single = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\'' => {
                single = !single;
                cur.push(c);
            }
            '$' if !single && chars.peek() == Some(&'(') => {
                chars.next();
                cur.push_str("SUBST");
                outer.push(std::mem::take(&mut cur));
            }
            ')' if !single && !outer.is_empty() => {
                out.push(std::mem::replace(&mut cur, outer.pop().unwrap_or_default()));
            }
            '&' | '|' | ';' | '(' | ')' | '{' | '}' if !single => {
                out.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out.extend(outer);
    out.into_iter().filter(|p| !p.trim().is_empty()).collect()
}

/// The `nn-admin` command a simple command runs, if any (its words after
/// `nn-admin`): past a prompt (`$`), a shell keyword (`if`, `then`, `!`, …),
/// variables set before it (`VAR=1`), `sudo` and its options (`-E`, `-u
/// user`), `env` with its options and variables, `exec`, `time`, `nohup`,
/// `command`, `timeout` and its duration, `watch` and its interval, and a
/// unit's `ExecStart=`; `nn-admin` by its name or a path to it.
fn nn_admin_words(command: &str) -> Option<Vec<String>> {
    let words = shell_words(command.trim());
    let mut i = 0;
    let assignment = |w: &str| {
        w.split_once('=').is_some_and(|(k, _)| {
            !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
    };
    while i < words.len() {
        let w = words[i].strip_prefix("ExecStart=").unwrap_or(&words[i]);
        if w.is_empty() {
            i += 1;
            continue;
        }
        if w == "nn-admin" || w.ends_with("/nn-admin") {
            return Some(words[i + 1..].to_vec());
        }
        let wrapper = |name: &str, with_value: &[&str]| -> Option<usize> {
            (w == name).then(|| {
                let mut k = i + 1;
                while k < words.len() && (words[k].starts_with('-') || assignment(&words[k])) {
                    k += 1 + usize::from(with_value.contains(&words[k].as_str()));
                }
                k
            })
        };
        if let Some(k) = wrapper(
            "sudo",
            &["-u", "-g", "-C", "-D", "-p", "-r", "-t", "-U", "-h"],
        )
        .or_else(|| wrapper("env", &["-u", "-C", "-S"]))
        .or_else(|| wrapper("watch", &["-n", "-d"]))
        {
            i = k;
            continue;
        }
        if let Some(k) = wrapper("timeout", &["-s", "-k"]) {
            i = k + 1; // its duration
            continue;
        }
        if matches!(
            w,
            "$" | "if"
                | "then"
                | "else"
                | "elif"
                | "do"
                | "while"
                | "until"
                | "!"
                | "time"
                | "exec"
                | "nohup"
                | "command"
        ) || assignment(w)
        {
            i += 1;
            continue;
        }
        return None;
    }
    None
}

/// Every `nn-admin` command line in the fenced blocks of `text` (its words
/// after `nn-admin`), with its line number: each simple command of the line
/// ([`simple_commands`]) that runs `nn-admin` ([`nn_admin_words`]) — prose
/// quoting a command in a sample output does not; a line ending in `\` goes
/// on.
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
        let at = i;
        let mut joined = line.to_string();
        while joined.ends_with('\\') && i < lines.len() {
            joined.pop();
            joined.push(' ');
            joined.push_str(lines[i].trim());
            i += 1;
        }
        for c in simple_commands(&joined) {
            if let Some(words) = nn_admin_words(&c) {
                out.push((at, words));
            }
        }
    }
    out
}

/// Lot 1.7b (the review of #593, finding 4): the `nn-admin` commands of the
/// prose's code spans (`` `sudo nn-admin unlock --key "$KEY"` ``, a span
/// over two lines of a paragraph too), with the line it starts on and
/// whether it gives a command to run (`sudo` or a prompt first) or names one
/// (`` `nn-admin status --key` ``).
fn prose_commands(text: &str) -> Vec<(usize, bool, Vec<String>)> {
    // the prose, the fenced blocks blanked (their lines kept, for the
    // numbers)
    let mut prose = String::new();
    let mut fenced = false;
    for line in text.lines() {
        if line.trim().starts_with("```") {
            fenced = !fenced;
        } else if !fenced {
            prose.push_str(line);
        }
        prose.push('\n');
    }
    let b: Vec<char> = prose.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let mut line = 1;
    while i < b.len() {
        if b[i] == '\n' {
            line += 1;
        }
        if b[i] != '`' {
            i += 1;
            continue;
        }
        let run = b[i..].iter().take_while(|c| **c == '`').count();
        let start = i + run;
        // the close: the next run of as many backticks, in the paragraph
        let mut k = start;
        let mut close = None;
        while k < b.len() {
            if b[k] == '\n' && b.get(k + 1) == Some(&'\n') {
                break;
            }
            if b[k] == '`' {
                let n = b[k..].iter().take_while(|c| **c == '`').count();
                if n == run {
                    close = Some(k);
                    break;
                }
                k += n;
                continue;
            }
            k += 1;
        }
        let Some(end) = close else {
            i = start;
            continue;
        };
        let span: String = b[start..end]
            .iter()
            .map(|c| if *c == '\n' { ' ' } else { *c })
            .collect();
        let span = span.trim();
        if span.contains("nn-admin") {
            let run_it = span.starts_with("sudo ") || span.starts_with("$ ");
            for c in simple_commands(span) {
                if let Some(words) = nn_admin_words(&c) {
                    if !words.is_empty() {
                        out.push((line, run_it, words));
                    }
                }
            }
        }
        line += b[start..end].iter().filter(|c| **c == '\n').count();
        i = end + run;
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
        // lot 2.3b (`window-run -- <command>`): a bare `--` ends the options;
        // what follows is the command's own, one trailing positional
        if w == "--" {
            positionals += usize::from(i + 1 < words.len());
            break;
        }
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

/// What is wrong with the command a prose span names, if anything: a
/// command or a group of the matrix (a placeholder for it passes), and only
/// options it has — a name, not a run, so a value or a required option may
/// be left out.
fn problem_named(cmds: &BTreeMap<Vec<String>, Command>, words: &[String]) -> Option<String> {
    if words
        .iter()
        .any(|w| w == "--version" || w == "--help" || w == "-h")
        || words
            .first()
            .is_some_and(|w| w == "PLACEHOLDER" || w.starts_with('-'))
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
    if let Some(next) = words.get(n).filter(|w| c.parent && !w.starts_with('-')) {
        if next != "PLACEHOLDER" {
            return Some(format!("`{}` has no command `{next}`", path.join(" ")));
        }
    }
    for w in words[n..].iter().take_while(|w| *w != "--") {
        if w.starts_with('-') && w.len() > 1 {
            let name = w.split_once('=').map_or(w.as_str(), |(k, _)| k);
            if !c.options.contains_key(name) {
                return Some(format!("`{}` has no option `{name}`", path.join(" ")));
            }
        }
    }
    None
}

/// Lot 1.7b: what the prose names that `nn-admin` does not take, left for the
/// documents' lot: `(document, the command as read, the lot that owns it,
/// the rule it breaks)`. Lot 1.9 paid the one entry (`UPGRADE_NOTES_WAVE4.md`'s
/// `heartbeat verify --max-skew-secs`, now `heartbeat watch`'s option): a new
/// entry needs an owner and the rule it breaks.
const PROSE_DEBT: &[(&str, &str, &str, &str)] = &[];

/// Every `nn-admin` command the README and the operator guides give is one
/// `nn-admin` takes, by its own help.
#[test]
fn every_documented_nn_admin_command_is_one_nn_admin_takes() {
    let cmds = commands();
    assert!(cmds.len() >= 60, "only {} commands in {HELP}", cmds.len());
    let mut checked = 0;
    let mut wrong = Vec::new();
    let mut debts: Vec<(String, String)> = Vec::new();
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
        // lot 1.7b: and the prose's code spans
        for (line, run, words) in prose_commands(&text) {
            checked += 1;
            let p = if run {
                problem(&cmds, &words)
            } else {
                problem_named(&cmds, &words)
            };
            let debt = PROSE_DEBT
                .iter()
                .any(|(d, c, _, _)| *d == name && *c == words.join(" "));
            if debt {
                debts.push((name.clone(), words.join(" ")));
                continue;
            }
            if let Some(p) = p {
                wrong.push(format!(
                    "{name}:{line}: `nn-admin {}` (prose): {p}",
                    words.join(" ")
                ));
            }
        }
    }
    assert!(checked >= 40, "only {checked} documented commands found");
    for (doc, command, owner, rule) in PROSE_DEBT {
        assert!(
            debts.iter().any(|(d, c)| d == doc && c == command),
            "{doc}: `nn-admin {command}` is listed in PROSE_DEBT and gone: remove the entry"
        );
        assert!(
            owner.starts_with("lot ") && rule.len() > 40,
            "{doc}: an owner and a rule"
        );
        let cmds = commands();
        let words: Vec<String> = command.split_whitespace().map(str::to_string).collect();
        assert!(
            problem_named(&cmds, &words).is_some(),
            "{doc}: `nn-admin {command}` is fine now: remove the entry"
        );
    }
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
    assert!(
        say(&["detections", "--limit", "20"])
            .unwrap()
            .contains("requires `--key`")
    );
    assert!(
        say(&["detections", "--key"])
            .unwrap()
            .contains("without its value")
    );
    assert!(
        say(&["audit", "verify", "--form", "x"])
            .unwrap()
            .contains("no option")
    );
    assert!(say(&["audit", "verfy"]).unwrap().contains("names a group"));
    assert!(say(&["nosuch"]).unwrap().contains("no command"));
    // lot 2.3b: `--` ends the options, the command after it is checked as
    // nothing of nn-admin's; an option before it still is
    assert_eq!(
        say(&["window-run", "--key", "k", "--", "apt", "--yes"]),
        None
    );
    assert!(
        say(&["window-run", "--key", "k", "--nosuch", "--", "apt"])
            .unwrap()
            .contains("no option")
    );
    assert!(
        say(&["window-run", "--key", "k", "--"])
            .unwrap()
            .contains("positional")
    );
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
    assert!(
        problem(&old, &w(&["audit", "verify"]))
            .unwrap()
            .contains("requires `--from`")
    );
}

/// A name in kebab case, as clap derives a command's from its variant
/// (`HostCheck`: `host-check`, `IOCList`: `ioc-list`).
fn kebab(ident: &str) -> String {
    let c: Vec<char> = ident.chars().collect();
    let mut out = String::new();
    for (i, ch) in c.iter().enumerate() {
        let boundary = i > 0
            && ch.is_ascii_uppercase()
            && (c[i - 1].is_ascii_lowercase()
                || c[i - 1].is_ascii_digit()
                || (c[i - 1].is_ascii_uppercase()
                    && c.get(i + 1).is_some_and(|n| n.is_ascii_lowercase())));
        if boundary {
            out.push('-');
        }
        out.push(ch.to_ascii_lowercase());
    }
    out
}

/// What a `#[command(…)]`/`#[clap(…)]` attribute list says: `(name =,
/// hide = true, subcommand)`.
fn command_attrs(attrs: &[syn::Attribute]) -> (Option<String>, bool, bool) {
    let (mut name, mut hide, mut sub) = (None, false, false);
    for a in attrs {
        if !(a.path().is_ident("command") || a.path().is_ident("clap")) {
            continue;
        }
        let _ = a.parse_nested_meta(|m| {
            if m.path.is_ident("name") {
                let v: syn::LitStr = m.value()?.parse()?;
                name = Some(v.value());
            } else if m.path.is_ident("hide") {
                hide = m
                    .value()
                    .and_then(|v| v.parse::<syn::LitBool>())
                    .map_or(true, |b| b.value);
            } else if m.path.is_ident("subcommand") {
                sub = true;
            } else if m.input.peek(syn::token::Eq) {
                let _: syn::Expr = m.value()?.parse()?;
            }
            Ok(())
        });
    }
    (name, hide, sub)
}

/// The type a field holds a command in (`Option<T>`: `T`).
fn command_type(ty: &syn::Type) -> Option<String> {
    let syn::Type::Path(p) = ty else {
        return None;
    };
    let seg = p.path.segments.last()?;
    if seg.ident == "Option" || seg.ident == "Box" {
        if let syn::PathArguments::AngleBracketed(a) = &seg.arguments {
            if let Some(syn::GenericArgument::Type(t)) = a.args.first() {
                return command_type(t);
            }
        }
    }
    Some(seg.ident.to_string())
}

/// Each `Subcommand` enum's variants: `(command, hidden, the type of its
/// subcommands)`.
type Variants = BTreeMap<String, Vec<(String, bool, Option<String>)>>;

/// Lot 1.7b: the commands `nn-admin`'s code defines, read as Rust (its
/// production code): clap's derive — the `Parser`'s `#[command(subcommand)]`
/// field, each `Subcommand` enum's variants (named by `#[command(name =
/// …)]` or their name in kebab case, `hide = true` left out), a variant's
/// subcommands through its `#[command(subcommand)]` field, its tuple's
/// `Subcommand` enum or its `Args` struct's subcommand field; a variant only
/// the lab's `debug-trigger` build has left out — and the builder (`Command::new("x")` under `.subcommand(…)` of
/// `Command::new("p")`, `.hide(true)` left out): each command by its words
/// after `nn-admin`.
fn defined_commands(sources: &BTreeMap<String, String>) -> BTreeSet<Vec<String>> {
    let parsed = ast::parse_all(sources, true);
    let c = ast::Corpus::of(sources, &parsed);
    let derives = |attrs: &[syn::Attribute], what: &str| {
        attrs
            .iter()
            .any(|a| a.path().is_ident("derive") && ast::compact(&a.meta).contains(what))
    };
    // variants: (name, hidden, child type); structs: their subcommand's type
    let mut enums: Variants = BTreeMap::new();
    let mut structs: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut roots: Vec<Option<String>> = Vec::new();
    struct Items<'v> {
        out: &'v mut Vec<syn::Item>,
    }
    impl<'a> Visit<'a> for Items<'_> {
        fn visit_item(&mut self, i: &'a syn::Item) {
            if matches!(i, syn::Item::Enum(_) | syn::Item::Struct(_)) {
                self.out.push(i.clone());
            }
            syn::visit::visit_item(self, i);
        }
    }
    let mut items = Vec::new();
    for f in parsed.values() {
        Items { out: &mut items }.visit_file(f);
    }
    let sub_field = |fields: &syn::Fields| -> Option<String> {
        fields
            .iter()
            .find(|f| command_attrs(&f.attrs).2)
            .and_then(|f| command_type(&f.ty))
    };
    for item in &items {
        match item {
            syn::Item::Struct(st) => {
                let child = sub_field(&st.fields);
                if derives(&st.attrs, "Parser") {
                    roots.push(child.clone());
                }
                structs.insert(st.ident.to_string(), child);
            }
            syn::Item::Enum(en) if derives(&en.attrs, "Subcommand") => {
                let mut vs = Vec::new();
                for v in &en.variants {
                    // the lab's build only: the matrix is the release
                    // binary's help
                    if v.attrs.iter().any(|a| {
                        a.path().is_ident("cfg")
                            && ast::compact(&a.meta) == "cfg(feature=\"debug-trigger\")"
                    }) {
                        continue;
                    }
                    let (name, hide, _) = command_attrs(&v.attrs);
                    let name = name.unwrap_or_else(|| kebab(&v.ident.to_string()));
                    let child = match &v.fields {
                        syn::Fields::Unnamed(u) if u.unnamed.len() == 1 => {
                            command_type(&u.unnamed[0].ty)
                        }
                        f => sub_field(f),
                    };
                    vs.push((name, hide, child));
                }
                enums.insert(en.ident.to_string(), vs);
            }
            _ => {}
        }
    }
    let mut out = BTreeSet::new();
    fn walk(
        ty: &str,
        path: &[String],
        enums: &Variants,
        structs: &BTreeMap<String, Option<String>>,
        out: &mut BTreeSet<Vec<String>>,
        depth: u8,
    ) {
        let ty = match (enums.contains_key(ty), structs.get(ty)) {
            (true, _) => ty.to_string(),
            (false, Some(Some(inner))) => inner.clone(),
            _ => return,
        };
        let Some(vs) = enums.get(&ty) else {
            return;
        };
        if depth > 8 {
            return;
        }
        for (name, hide, child) in vs {
            if *hide {
                continue;
            }
            let mut p = path.to_vec();
            p.push(name.clone());
            out.insert(p.clone());
            if let Some(ch) = child {
                walk(ch, &p, enums, structs, out, depth + 1);
            }
        }
    }
    for r in roots.into_iter().flatten() {
        walk(&r, &[], &enums, &structs, &mut out, 0);
    }
    // the builder: `parent.subcommand(child)`, each a `Command::new(name)`
    let mut edges: Vec<(String, String, bool)> = Vec::new();
    let mut named: BTreeSet<String> = BTreeSet::new();
    for (rel, ix) in &c.files {
        let command_new = |e: &syn::Expr| -> Option<(String, bool)> {
            // the root of `e`'s method chain, a `Command::new("…")`, and
            // whether the chain hides it
            let mut cur = ast::peel(e);
            let mut hide = false;
            loop {
                match cur {
                    syn::Expr::MethodCall(m) => {
                        if m.method == "hide"
                            && m.args.first().is_some_and(|a| ast::compact(a) == "true")
                        {
                            hide = true;
                        }
                        cur = ast::peel(&m.receiver);
                    }
                    syn::Expr::Call(call) => {
                        let syn::Expr::Path(p) = ast::peel(&call.func) else {
                            return None;
                        };
                        let full = ix.full_paths(&ast::segments(&p.path));
                        if !full.iter().any(|f| ast::path_ends(f, &["Command", "new"])) {
                            return None;
                        }
                        let v = c.values(rel, call.args.first()?, None);
                        return v.first().map(|n| (n.clone(), hide));
                    }
                    _ => return None,
                }
            }
        };
        for call in &ix.calls {
            if call.name == "new" {
                if let Some((n, _)) = command_new(call.expr) {
                    named.insert(n);
                }
            }
            if call.name != "subcommand" {
                continue;
            }
            let (Some(recv), Some(arg)) = (call.receiver, call.args.first()) else {
                continue;
            };
            if let (Some((p, _)), Some((ch, hide))) = (command_new(recv), command_new(arg)) {
                edges.push((p, ch, hide));
            }
        }
    }
    let children: BTreeSet<&String> = edges.iter().map(|(_, ch, _)| ch).collect();
    let mut todo: Vec<(String, Vec<String>)> = named
        .iter()
        .filter(|n| !children.contains(n) && edges.iter().any(|(p, _, _)| p == *n))
        .map(|n| (n.clone(), Vec::new()))
        .collect();
    while let Some((node, path)) = todo.pop() {
        for (p, ch, hide) in &edges {
            if p == &node && !hide && path.len() < 8 {
                let mut q = path.clone();
                q.push(ch.clone());
                out.insert(q.clone());
                todo.push((ch.clone(), q));
            }
        }
    }
    out
}

/// Lot 1.7b: the help matrix the documents are checked against names every
/// command `nn-admin`'s code defines and no other (clap's own `help`
/// command aside): the truth is complete, so a command's help is in the
/// matrix that `operator_help.rs` reads too.
#[test]
fn the_matrix_names_every_command_the_code_defines() {
    let sources = ast::tree_sources(&repo_root(), "crates/nn-admin/src");
    let defined = defined_commands(&sources);
    assert!(defined.len() >= 60, "{} commands defined", defined.len());
    let matrix: BTreeSet<Vec<String>> = commands()
        .into_keys()
        // clap's own `help`; a case that asks a command's help after one of
        // its options (`audit read --json --help`) names no other command
        .filter(|p| !p.iter().any(|w| w == "help" || w.starts_with('-')))
        .collect();
    let missing: Vec<&Vec<String>> = defined.difference(&matrix).collect();
    let extra: Vec<&Vec<String>> = matrix.difference(&defined).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "commands the code defines and the matrix lacks: {missing:?}; in the matrix, not in \
         the code: {extra:?}"
    );
}

/// The reader of command definitions sees clap's derive and builder forms:
/// a renamed, a hidden, a nested (by a field, a tuple's enum, an `Args`
/// struct's field) command, and a builder's tree.
#[test]
fn the_command_reader_sees_derive_and_builder_forms() {
    let derive = r#"
        #[derive(clap::Parser)]
        struct Cli { #[command(subcommand)] cmd: Cmd }
        #[derive(clap::Subcommand)]
        enum Cmd {
            HostCheck,
            #[command(name = "renamed")]
            Old { x: u8 },
            #[command(hide = true)]
            Secret,
            Audit { #[command(subcommand)] op: AuditCmd },
            Chain(ChainCmd),
            Net(NetArgs),
        }
        #[derive(clap::Subcommand)]
        enum AuditCmd { Verify, Read }
        #[derive(clap::Subcommand)]
        enum ChainCmd { Verify }
        #[derive(clap::Args)]
        struct NetArgs { #[command(subcommand)] op: Option<NetCmd> }
        #[derive(clap::Subcommand)]
        enum NetCmd { Flows }
    "#;
    let builder = r#"
        use clap::Command;
        fn cli() -> Command {
            Command::new("nn-admin")
                .subcommand(Command::new("status"))
                .subcommand(Command::new("debug").hide(true))
                .subcommand(clap::Command::new("fim").subcommand(Command::new("report")))
        }
    "#;
    let w = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    let one = |t: &str| {
        defined_commands(&[("crates/nn-admin/src/planted.rs".to_string(), t.to_string())].into())
    };
    let d = one(derive);
    let want: BTreeSet<Vec<String>> = [
        w(&["host-check"]),
        w(&["renamed"]),
        w(&["audit"]),
        w(&["audit", "verify"]),
        w(&["audit", "read"]),
        w(&["chain"]),
        w(&["chain", "verify"]),
        w(&["net"]),
        w(&["net", "flows"]),
    ]
    .into();
    assert_eq!(d, want);
    assert_eq!(
        ["HostCheck", "HTTPServer", "IocList", "Fim2Report"].map(kebab),
        ["host-check", "http-server", "ioc-list", "fim2-report"]
    );
    let b = one(builder);
    let want: BTreeSet<Vec<String>> = [w(&["status"]), w(&["fim"]), w(&["fim", "report"])].into();
    assert_eq!(b, want);
}

/// Lot 1.7b (the review of #593, finding 4, and the mini-hunt): the shapes
/// the reader before it missed, each a wrong command (`host-check --bogus`)
/// planted in a document — in a command substitution, after `sudo`'s
/// options, a variable set before `sudo` or by `env`, an `if`, a list
/// (`&&`, `||`), `timeout` and `watch`, a value from a substitution, and a
/// prose span to run (a span over two lines too). The reader before found
/// none, this one finds each and the checker refuses it.
#[test]
fn the_lexical_bypasses_are_caught() {
    let cmds = commands();
    let fenced = |line: &str| format!("x\n```sh\n{line}\n```\n");
    for shape in [
        "x=$(sudo nn-admin host-check --bogus)",
        "sudo -E nn-admin host-check --bogus",
        "sudo -u root nn-admin host-check --bogus",
        "VAR=1 sudo nn-admin host-check --bogus",
        "sudo env FOO=1 nn-admin host-check --bogus",
        "if sudo nn-admin host-check --bogus; then",
        "sudo nn-admin status && sudo nn-admin host-check --bogus",
        "true || nn-admin host-check --bogus",
        "timeout 5 nn-admin host-check --bogus",
        "watch -n 5 nn-admin host-check --bogus",
        "echo \"$(nn-admin host-check --bogus)\"",
    ] {
        let text = fenced(shape);
        let old: Vec<String> = lexical::documented(&text)
            .into_iter()
            .filter_map(|(_, w)| problem(&cmds, &w))
            .collect();
        assert!(old.is_empty(), "the reader before saw it: {shape}: {old:?}");
        let new: Vec<String> = documented(&text)
            .into_iter()
            .filter_map(|(_, w)| problem(&cmds, &w))
            .collect();
        assert!(
            new.iter().any(|p| p.contains("no option `--bogus`")),
            "{shape}: {new:?}"
        );
    }
    // a value from a substitution is a value
    assert_eq!(
        documented(&fenced(
            "nn-admin audit verify --from a --agent-pubkey \"$(cat k)\""
        )),
        vec![(
            3,
            ["audit", "verify", "--from", "a", "--agent-pubkey", "SUBST"]
                .map(String::from)
                .to_vec()
        ),]
    );
    for prose in [
        "Clean up with `sudo nn-admin host-check --bogus` afterwards.\n",
        "then, `sudo nn-admin host-check\n--bogus` (over two lines).\n",
        "Check `sudo nn-admin audit verify && sudo nn-admin host-check --bogus`.\n",
    ] {
        assert!(
            lexical::documented(prose).is_empty(),
            "the reader before saw it: {prose}"
        );
        let found: Vec<String> = prose_commands(prose)
            .into_iter()
            .filter_map(|(_, run, w)| {
                if run {
                    problem(&cmds, &w)
                } else {
                    problem_named(&cmds, &w)
                }
            })
            .collect();
        assert!(
            found.iter().any(|p| p.contains("no option `--bogus`")),
            "{prose}: {found:?}"
        );
    }
    // a name in prose is checked as a name: a group, an option without its
    // value pass; a command or an option nn-admin lacks does not
    let named = |s: &str| {
        prose_commands(s)
            .into_iter()
            .map(|(_, _, w)| problem_named(&cmds, &w))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        named("see `nn-admin audit` and `nn-admin status --key`\n"),
        [None, None]
    );
    assert!(named("see `nn-admin heartbeat verify`\n")[0].is_some());
    assert!(named("see `nn-admin audit read --key …`\n")[0].is_some());
    // a span to run is checked as a command: its required option too
    let run = prose_commands("run `sudo nn-admin detections --limit 20` now\n");
    assert_eq!(run.len(), 1);
    assert!(run[0].1, "a span after sudo is a command to run");
    assert!(
        problem(&cmds, &run[0].2)
            .unwrap()
            .contains("requires `--key`")
    );
    assert!(!prose_commands("see `nn-admin detections --limit 20`\n")[0].1);
}

/// The reader before lot 1.7b (a line of a fenced block that starts with
/// `nn-admin` past a prompt, `sudo`, `{` or `ExecStart=`), kept only to
/// show the shapes it missed.
mod lexical {
    use super::shell_words;

    /// Every `nn-admin` command line in the fenced blocks of `text` (its words
    /// after `nn-admin`), with its line number: the line, past a prompt,
    /// `sudo`, a group's `{` or a unit's `ExecStart=`, starts with `nn-admin`
    /// (prose quoting a command in a sample output does not); a line ending in
    /// `\` goes on.
    pub fn documented(text: &str) -> Vec<(usize, Vec<String>)> {
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
}
