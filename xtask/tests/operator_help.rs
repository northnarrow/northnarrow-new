//! Lot 354 (pre-alpha, the operator's help, the audit's T7): what an
//! operator reads when they ask for help speaks their language. The help of
//! `nn-admin` (every case of the generated help matrix, which `cargo xtask
//! golden` checks against the binary), of `install.sh`, of `uninstall.sh`
//! and (lot 377) of the two daemons (`northnarrow-agent --help` and
//! `northnarrow-watchdog --help`, the golden files their unit tests check
//! against the binaries' command lines) names no lot, review, audit finding,
//! design section, development stage or internal crate; every option the
//! scripts accept is in their help; and
//! the scripts print no colour (so `NO_COLOR` holds for them), and every
//! binary's colour obeys `NO_COLOR` (nn-admin's one helper, the daemons'
//! log layer).
//!
//! Lot 1.7b (stage S1, item F12): the colour rules read the code as Rust
//! (`support::ast`) — a terminal check by any name or passed as a value,
//! the statement around it asking `NO_COLOR`; an escape however a literal
//! makes it; a fmt layer by any path — and the scan before it (kept in
//! [`lexical`] only to show it) missed each spelling planted in
//! `the_lexical_colour_bypasses_are_caught`. Each daemon's golden help is
//! held to the options its clap code defines (derive and builder forms,
//! read as Rust): every shown option listed, no hidden one, none more — so
//! the jargon scan reads every option's help. (`nn-admin`'s commands are
//! held to its matrix in `documented_commands.rs`.)

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::process::Command;

mod support;

use support::ast;
use support::repo_root;

fn read(rel: &str) -> String {
    let path = repo_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Words of the project's history that mean nothing to an operator.
const JARGON: [&str; 31] = [
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
    // lot 377: the daemons' help
    "Beta Step",
    "soak cycle",
    "Repo dev path",
    "F10-",
    "R9-",
    "R10-",
    // the internal crates and modules, as a path or a package name
    "nn_linux",
    "nn-linux",
    "northnarrow_agent",
    "antitamper_bpf",
    "antitamper-bpf",
    "nn_core",
    "nn_proto",
    "common::",
];

/// The internal reference `line` makes, if any: a word of [`JARGON`], a
/// lot number, a review number (`review 26`), a pull request number, an
/// audit finding's id (`ASK-009`, not a rule id such as `NN-L-FIM-009`), a
/// review finding's (`R10-1`, `F9-2`), a design question (`Q6`), a
/// development wave's step (`W6`) or a section sign that follows no
/// operator guide.
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
        let word_start = i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
        let digits = rest.bytes().skip(1).take_while(u8::is_ascii_digit).count();
        // a development wave's step: `W` and digits, a whole word
        if w == 'W'
            && word_start
            && digits > 0
            && !b
                .get(i + 1 + digits)
                .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
        {
            return Some(rest.chars().take(1 + digits).collect());
        }
        // a review finding: a capital, digits, `-`, a digit (`R10-1`)
        if w.is_ascii_uppercase()
            && word_start
            && digits > 0
            && b.get(i + 1 + digits) == Some(&b'-')
            && digit_after(digits + 2)
        {
            return Some(rest.chars().take(digits + 3).collect());
        }
        // a review's number
        let lower = rest.to_ascii_lowercase();
        if word_start {
            for word in ["review ", "reviews "] {
                if lower.starts_with(word) && digit_after(word.len()) {
                    return Some(rest.chars().take(word.len() + 2).collect());
                }
            }
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

/// The options a daemon's rendered help lists (`  -h, --help`,
/// `      --detect-only`; not the `- value:` lines of a list of values).
fn listed_options(help: &str) -> usize {
    help.lines()
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with('-') && l.len() - t.len() <= 6
        })
        .count()
}

/// Lot 377: the daemons' `--help`, as their unit tests hold it to the
/// binaries' command lines (`the_help_is_the_checked_in_text`), and the
/// fewest options each lists (so a deleted or emptied file cannot pass).
const DAEMON_HELP: [(&str, usize); 2] = [
    ("agent/tests/golden/help/northnarrow-agent.txt", 40),
    ("watchdog/tests/golden/help/northnarrow-watchdog.txt", 10),
];

#[test]
fn the_help_speaks_the_operator_s_language() {
    let mut problems = jargon_lines("nn-admin --help", &nn_admin_help());
    for script in ["deploy/install.sh", "deploy/uninstall.sh"] {
        problems.extend(jargon_lines(script, &script_help(script)));
    }
    for (golden, fewest) in DAEMON_HELP {
        let help = read(golden);
        let options = listed_options(&help);
        assert!(
            options >= fewest,
            "{golden}: {options} options listed, {fewest} at least"
        );
        problems.extend(jargon_lines(golden, &help));
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

/// The review of #562 (R2): no tracked shell script writes an ANSI colour
/// (every `*.sh` and every file whose `#!` names a shell: the install and
/// uninstall scripts, the package hooks, the release and lab scripts), so
/// nothing they say is carried by a colour and `NO_COLOR` holds for them as
/// it is.
#[test]
fn the_scripts_print_no_colour() {
    let mut scripts = Vec::new();
    for rel in support::tracked_files() {
        let Ok(text) = fs::read_to_string(repo_root().join(&rel)) else {
            continue;
        };
        let first = text.lines().next().unwrap_or("");
        let shell = first.starts_with("#!")
            && ["sh", "bash", "dash"]
                .iter()
                .any(|s| first.ends_with(&format!("/{s}")) || first.ends_with(&format!(" {s}")));
        if !rel.ends_with(".sh") && !shell {
            continue;
        }
        for (n, line) in text.lines().enumerate() {
            for esc in [
                "\\033[",
                "\\e[",
                "\\x1b[",
                "\\x1B[",
                "\\u001b[",
                "tput setaf",
                "tput setab",
                "tput bold",
                "tput sgr",
            ] {
                assert!(
                    !line.contains(esc),
                    "{rel}:{}: prints a colour ({esc}): {line}",
                    n + 1
                );
            }
        }
        scripts.push(rel);
    }
    for needed in [
        "deploy/install.sh",
        "deploy/uninstall.sh",
        "deploy/release/pkg/postinst.sh",
        "deploy/release/mk-tarball.sh",
    ] {
        assert!(scripts.iter().any(|s| s == needed), "{needed} not scanned");
    }
    for script in ["deploy/install.sh", "deploy/uninstall.sh"] {
        assert!(!script_help(script).contains('\u{1b}'), "{script} --help");
    }
}

/// The terminal checks of the code: by their name or a path to them,
/// called or passed as a value (`.map(IsTerminal::is_terminal)`), under an
/// import's other name.
const TERMINAL_CHECKS: [&str; 2] = ["is_terminal", "isatty"];

/// The fmt layers and builders of `tracing_subscriber` (their colour is on
/// by default).
const FMT_LAYERS: [&[&str]; 6] = [
    &["tracing_subscriber", "fmt"],
    &["tracing_subscriber", "fmt", "layer"],
    &["tracing_subscriber", "fmt", "Layer", "default"],
    &["tracing_subscriber", "fmt", "Layer", "new"],
    &["tracing_subscriber", "fmt", "Subscriber", "builder"],
    &["tracing_subscriber", "FmtSubscriber", "builder"],
];

/// The statement a site is in, as tokens: the `let` it is in, else the
/// expression its statement is (up through operands, an `if`'s condition, a
/// `match`'s scrutinee — not a block's, a closure's or a branch's body).
fn statement_tokens(e: &syn::Expr, anc: &[ast::Anc<'_>]) -> proc_macro2::TokenStream {
    use quote::ToTokens;
    let mut cur = e;
    for a in anc.iter().rev() {
        match a {
            ast::Anc::Local(l) => return l.to_token_stream(),
            ast::Anc::Expr(p) => {
                let stop = match p {
                    syn::Expr::Block(_)
                    | syn::Expr::Unsafe(_)
                    | syn::Expr::Closure(_)
                    | syn::Expr::Loop(_)
                    | syn::Expr::While(_)
                    | syn::Expr::ForLoop(_)
                    | syn::Expr::Async(_)
                    | syn::Expr::Const(_) => true,
                    syn::Expr::If(i) => !std::ptr::eq(&*i.cond, cur),
                    syn::Expr::Match(m) => !std::ptr::eq(&*m.expr, cur),
                    _ => false,
                };
                if stop {
                    break;
                }
                cur = p;
            }
        }
    }
    cur.to_token_stream()
}

/// Whether `tokens` name `NO_COLOR` (a literal) or call `colour_on`.
fn asks_no_color(tokens: proc_macro2::TokenStream) -> bool {
    tokens.into_iter().any(|t| match t {
        proc_macro2::TokenTree::Literal(l) => l.to_string() == "\"NO_COLOR\"",
        proc_macro2::TokenTree::Ident(i) => i == "colour_on",
        proc_macro2::TokenTree::Group(g) => asks_no_color(g.stream()),
        _ => false,
    })
}

/// Whether a literal holding the escape character is a piece of text, not
/// a byte table's (a file signature's bytes, not UTF-8, other controls).
fn piece(v: &str) -> bool {
    v.chars()
        .all(|c| c != '\u{fffd}' && (!c.is_control() || matches!(c, '\u{1b}' | '\n' | '\t')))
}

/// Whether `text` opens a control sequence (`ESC [`) or an operating-system
/// command (`ESC ]`).
fn opens_escape(text: &str) -> bool {
    text.contains("\u{1b}[") || text.contains("\u{1b}]")
}

/// What the colour rules find in `sources` (production code, read as Rust):
/// `(problems, terminal checks, (file, item) writing an escape, layers with
/// a colour)`.
fn colour_scan(
    sources: &BTreeMap<String, String>,
) -> (Vec<String>, usize, BTreeSet<(String, String)>, usize) {
    let parsed = ast::parse_all(sources, true);
    let c = ast::Corpus::of(sources, &parsed);
    let (mut problems, mut checks, mut escapes, mut layers) = (Vec::new(), 0, BTreeSet::new(), 0);
    for (rel, ix) in &c.files {
        let names = |segs: &[String], list: &[&str]| {
            ix.full_paths(segs)
                .iter()
                .any(|f| list.contains(&f[f.len() - 1].as_str()))
        };
        let mut terminal = |line: usize, e: &syn::Expr, anc: &[ast::Anc<'_>]| {
            checks += 1;
            if !asks_no_color(statement_tokens(e, anc)) {
                problems.push(format!("{rel}:{line}: a terminal check without NO_COLOR"));
            }
        };
        for call in &ix.calls {
            let is_check = match &call.path {
                Some(p) => {
                    names(p, &TERMINAL_CHECKS)
                        || ix
                            .full_paths(p)
                            .iter()
                            .any(|f| ast::path_ends(f, &["atty", "is"]))
                }
                None => TERMINAL_CHECKS.contains(&call.name.as_str()),
            };
            if is_check {
                terminal(call.line, call.expr, &call.anc);
            }
        }
        for p in &ix.paths {
            let local =
                p.segs.len() == 1 && p.scope.is_some_and(|id| ix.fns[id].is_local(&p.segs[0]));
            if !p.called && !local && names(&p.segs, &TERMINAL_CHECKS) {
                terminal(p.line, p.expr, &p.anc);
            }
        }
        // an escape sequence: a literal that opens one, what `concat!`
        // joins, and any text literal holding the escape character (a piece
        // of one: `'\x1b'`, a constant `"\u{1b}"` a `format!` puts before
        // `[31m`) — every escape a binary writes starts as a literal
        for l in &ix.lits {
            if opens_escape(&l.value) || (l.value.contains('\u{1b}') && piece(&l.value)) {
                escapes.insert((rel.clone(), l.item.clone()));
            }
        }
        // a fmt layer's colour: `false`, or `stdout_ansi()` (which asks
        // NO_COLOR and the terminal)
        for call in &ix.calls {
            let ansi_arg = match (&call.path, call.name.as_str()) {
                (None, "with_ansi") => call.args.first(),
                (Some(_), "with_ansi") => call.args.get(1),
                _ => continue,
            };
            layers += 1;
            let fine = ansi_arg.is_some_and(|a| match ast::peel(a) {
                syn::Expr::Lit(l) => matches!(&l.lit, syn::Lit::Bool(b) if !b.value),
                syn::Expr::Call(x) => match ast::peel(&x.func) {
                    syn::Expr::Path(p) => ix
                        .full_paths(&ast::segments(&p.path))
                        .iter()
                        .any(|f| ast::path_ends(f, &["log_escape", "stdout_ansi"])),
                    _ => false,
                },
                _ => false,
            });
            if !fine {
                problems.push(format!(
                    "{rel}:{}: a colour not from stdout_ansi",
                    call.line
                ));
            }
        }
        for call in &ix.calls {
            let Some(p) = &call.path else {
                continue;
            };
            if !ix
                .full_paths(p)
                .iter()
                .any(|f| FMT_LAYERS.iter().any(|l| f == l))
            {
                continue;
            }
            let (_, chain, _) = ast::spine(call.expr, &call.anc);
            if !chain.iter().any(|m| m.method == "with_ansi") {
                problems.push(format!(
                    "{rel}:{}: a fmt layer with the default colour",
                    call.line
                ));
            }
        }
    }
    for (rel, item) in &escapes {
        let colorize = rel == "crates/nn-admin/src/cli.rs" && item == "colorize";
        if !colorize {
            problems.push(format!(
                "{rel}: `{item}` writes an escape sequence outside colorize"
            ));
        }
    }
    problems.sort();
    (problems, checks, escapes, layers)
}

/// The review of #562 (R2): in every binary's production code (every
/// product tree, comments and tests left out), a terminal check decides a
/// colour only next to `NO_COLOR` (nn-admin's `colour_on`, the daemons'
/// `stdout_ansi`), whatever its spelling (`.is_terminal()`,
/// `IsTerminal::is_terminal(…)`); an escape sequence is written only by
/// nn-admin's `colorize`; and a tracing fmt layer takes its colour from
/// `stdout_ansi` or has none. Lot 1.7b: read as Rust — a terminal check by
/// any name (`isatty`, an import's alias) or passed as a value, its
/// statement asking `NO_COLOR`; an escape however it is made (`concat!`, a
/// `format!` of an escape character or a constant); a fmt layer by any path
/// to it (`fmt::layer()`, an imported `fmt`).
#[test]
fn every_binary_s_colour_obeys_no_color() {
    let code = ast::product_sources(&repo_root());
    assert!(code.len() > 100, "{} files", code.len());
    let (problems, checks, escapes, layers) = colour_scan(&code);
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    assert!(
        checks >= 10 && escapes.len() == 1 && layers >= 2,
        "{checks} {escapes:?} {layers}"
    );
}

/// Lot 1.7b: the spellings the lexical scan missed, each planted in a copy
/// of the agent's `boot/logging.rs`: the lexical scan finds no more
/// problems, the AST scan more — a terminal check passed as a value or
/// by `isatty`, an escape a `format!` makes of an escape character or of a
/// constant, or `concat!` joins, a fmt layer by `fmt::layer()` or an
/// imported `fmt`.
#[test]
fn the_lexical_colour_bypasses_are_caught() {
    let host = "agent/src/boot/logging.rs";
    let text = read(host);
    let one = |t: &str| BTreeMap::from([(host.to_string(), t.to_string())]);
    let base = colour_scan(&one(&text)).0.len();
    let base_lex = lexical::colour_problems(&one(&text)).len();
    for plant in [
        "fn planted() -> bool { [std::io::stdout()].iter().map(std::io::IsTerminal::is_terminal).all(|t| t) }",
        "fn planted() -> bool { unsafe { libc::isatty(1) == 1 } }",
        "fn planted(s: &str) -> String { format!(\"{}[31m{s}\", '\\x1b') }",
        "const ESC: &str = \"\\u{1b}\";\nfn planted(s: &str) -> String { format!(\"{ESC}[1m{s}\") }",
        "fn planted() -> &'static str { concat!(\"\\x1b\", \"[0m\") }",
        "fn planted() -> impl Sized { tracing_subscriber::fmt::layer() }",
        "use tracing_subscriber::fmt;\nfn planted() { fmt().init(); }",
    ] {
        let copy = format!("{text}\n{plant}\n");
        assert_eq!(
            lexical::colour_problems(&one(&copy)).len(),
            base_lex,
            "the lexical scan saw it: {plant}"
        );
        let (p, _, _, _) = colour_scan(&one(&copy));
        assert!(p.len() > base, "{plant}: {p:#?}");
    }
}

/// The options a daemon's rendered help lists, by name (`--detect-only`,
/// `-h`).
fn listed_names(help: &str) -> BTreeSet<String> {
    help.lines()
        .filter(|l| {
            let t = l.trim_start();
            t.starts_with('-') && l.len() - t.len() <= 6
        })
        .flat_map(|l| {
            l.trim_start()
                .split(", ")
                .filter_map(|w| w.split([' ', '=', '<']).next())
                .filter(|w| w.starts_with('-'))
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Lot 1.7b: the options a daemon's code defines, read as Rust: clap's
/// derive (`#[arg(long)]`, `#[arg(long = "x", short)]`, a `#[command(flatten)]`
/// struct's) and builder (`Arg::new(…).long("x").short('x')`) forms —
/// `(visible, hidden)`, `--help` and (with `#[command(version)]`)
/// `--version` among the visible.
fn defined_options(sources: &BTreeMap<String, String>) -> (BTreeSet<String>, BTreeSet<String>) {
    let parsed = ast::parse_all(sources, true);
    let c = ast::Corpus::of(sources, &parsed);
    let (mut visible, mut hidden) = (BTreeSet::new(), BTreeSet::new());
    let mut structs: BTreeMap<String, &syn::ItemStruct> = BTreeMap::new();
    for f in parsed.values() {
        for item in &f.items {
            if let syn::Item::Struct(s) = item {
                structs.insert(s.ident.to_string(), s);
            }
        }
    }
    let derives = |s: &syn::ItemStruct, what: &str| {
        s.attrs
            .iter()
            .any(|a| a.path().is_ident("derive") && ast::compact(&a.meta).contains(what))
    };
    fn fields(
        s: &syn::ItemStruct,
        structs: &BTreeMap<String, &syn::ItemStruct>,
        visible: &mut BTreeSet<String>,
        hidden: &mut BTreeSet<String>,
        depth: u8,
    ) {
        for f in &s.fields {
            let field = f
                .ident
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default();
            let (mut long, mut short, mut hide, mut flatten) = (None, None, false, false);
            for a in &f.attrs {
                if !(a.path().is_ident("arg")
                    || a.path().is_ident("clap")
                    || a.path().is_ident("command"))
                {
                    continue;
                }
                let _ = a.parse_nested_meta(|m| {
                    let has_value = m.input.peek(syn::token::Eq);
                    if m.path.is_ident("long") {
                        long = Some(if has_value {
                            m.value()?.parse::<syn::LitStr>()?.value()
                        } else {
                            field.replace('_', "-")
                        });
                    } else if m.path.is_ident("short") {
                        short = Some(if has_value {
                            m.value()?.parse::<syn::LitChar>()?.value()
                        } else {
                            field.chars().next().unwrap_or('?')
                        });
                    } else if m.path.is_ident("hide") {
                        hide = !has_value || m.value()?.parse::<syn::LitBool>()?.value;
                    } else if m.path.is_ident("flatten") {
                        flatten = true;
                    } else if has_value {
                        let _: syn::Expr = m.value()?.parse()?;
                    } else if m.input.peek(syn::token::Paren) {
                        let _g: proc_macro2::Group = m.input.parse()?;
                    }
                    Ok(())
                });
            }
            if flatten && depth < 4 {
                if let syn::Type::Path(p) = &f.ty {
                    if let Some(inner) = structs.get(&ast::last(&p.path)) {
                        fields(inner, structs, visible, hidden, depth + 1);
                    }
                }
                continue;
            }
            let out = if hide { &mut *hidden } else { &mut *visible };
            if let Some(l) = long {
                out.insert(format!("--{l}"));
            }
            if let Some(s) = short {
                out.insert(format!("-{s}"));
            }
        }
    }
    for s in structs.values() {
        if !derives(s, "Parser") {
            continue;
        }
        visible.insert("--help".to_string());
        visible.insert("-h".to_string());
        let version = s.attrs.iter().any(|a| {
            a.path().is_ident("command")
                && ast::compact(&a.meta).replace(' ', "").contains("version")
        });
        if version {
            visible.insert("--version".to_string());
            visible.insert("-V".to_string());
        }
        fields(s, &structs, &mut visible, &mut hidden, 0);
    }
    // the builder: `Arg::new(…)` and its chain's `long`, `short`, `hide`
    for (rel, ix) in &c.files {
        for call in &ix.calls {
            let Some(p) = &call.path else {
                continue;
            };
            if !ix
                .full_paths(p)
                .iter()
                .any(|f| ast::path_ends(f, &["Arg", "new"]))
            {
                continue;
            }
            let (_, chain, _) = ast::spine(call.expr, &call.anc);
            let value = |m: &syn::ExprMethodCall| -> Option<String> {
                c.values(rel, m.args.first()?, call.scope)
                    .into_iter()
                    .next()
            };
            let hide = chain.iter().any(|m| {
                m.method == "hide" && m.args.first().is_some_and(|a| ast::compact(a) == "true")
            });
            let out = if hide { &mut hidden } else { &mut visible };
            for m in &chain {
                match m.method.to_string().as_str() {
                    "long" => {
                        if let Some(v) = value(m) {
                            out.insert(format!("--{v}"));
                        }
                    }
                    "short" => {
                        if let Some(v) = value(m) {
                            out.insert(format!("-{v}"));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    (visible, hidden)
}

/// Lot 1.7b: each daemon's checked-in help (the golden its unit test holds
/// to the binary) lists every option its code defines and shows, and none it
/// hides — so the jargon scan above reads every option's help.
#[test]
fn the_daemons_help_lists_every_option_their_code_defines() {
    for ((golden, _), src) in DAEMON_HELP
        .iter()
        .zip(["agent/src/boot/cli.rs", "watchdog/src/lib.rs"])
    {
        let text = read(src);
        let one = BTreeMap::from([(src.to_string(), text)]);
        let (visible, hidden) = defined_options(&one);
        let listed = listed_names(&read(golden));
        assert!(visible.len() >= 10, "{src}: {visible:?}");
        let missing: Vec<&String> = visible.difference(&listed).collect();
        let extra: Vec<&String> = listed.difference(&visible).collect();
        let shown: Vec<&String> = hidden.intersection(&listed).collect();
        assert!(
            missing.is_empty() && extra.is_empty() && shown.is_empty(),
            "{golden} against {src}: defined, not listed {missing:?}; listed, not defined \
             {extra:?}; hidden, listed {shown:?}"
        );
    }
}

/// The reader of options sees clap's derive and builder forms.
#[test]
fn the_option_reader_sees_derive_and_builder_forms() {
    let derive = r#"
        #[derive(clap::Parser)]
        #[command(name = "d", version)]
        struct Cli {
            #[arg(long = "detect-only", default_value_t = false)]
            detect_only: bool,
            #[arg(long, short)]
            verbose: bool,
            #[arg(short = 'q', long = "quiet")]
            q: bool,
            #[arg(long = "secret", hide = true)]
            secret: bool,
            #[command(flatten)]
            more: More,
            positional: Option<String>,
        }
        #[derive(clap::Args)]
        struct More {
            #[arg(long, value_parser = ["a", "b"])]
            mode: String,
        }
    "#;
    let builder = r#"
        use clap::{Arg, Command};
        fn cli() -> Command {
            Command::new("d")
                .arg(Arg::new("x").long("pid-file").short('p'))
                .arg(clap::Arg::new("y").long("debug").hide(true))
        }
    "#;
    let names = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<BTreeSet<_>>();
    let (v, h) = defined_options(&BTreeMap::from([("d.rs".to_string(), derive.to_string())]));
    assert_eq!(
        v,
        names(&[
            "--help",
            "-h",
            "--version",
            "-V",
            "--detect-only",
            "--verbose",
            "-v",
            "-q",
            "--quiet",
            "--mode"
        ])
    );
    assert_eq!(h, names(&["--secret"]));
    let (v, h) = defined_options(&BTreeMap::from([("b.rs".to_string(), builder.to_string())]));
    assert_eq!(v, names(&["--pid-file", "-p"]));
    assert_eq!(h, names(&["--debug"]));
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
        // lot 377
        ("Beta Step 4b: opt-in", true),
        ("kept for one soak cycle as a fallback", true),
        ("Repo dev path: configs/combat-rules.v4", true),
        ("the review's F10-3", true),
        ("(R9-2)", true),
        ("R10-1 and R10-2", true),
        ("F9-2: the move", true),
        ("crates/nn-linux/src", true),
        ("nn_linux::sensors", true),
        ("[`northnarrow_agent::removed_settings`]", true),
        ("northnarrow_agent::audit", true),
        ("antitamper_bpf::kernel_roots", true),
        ("the antitamper-bpf crate", true),
        ("nn_core::response", true),
        ("nn_proto::witness::WITNESS_DIR", true),
        ("common::wire::execq", true),
        ("Tappa 7 task 6 Watchdog W6: best-effort", true),
        ("W2/W3/W5", true),
        ("(W6)", true),
        ("Default (review 26): the", true),
        ("(reviews 66, 67)", true),
        ("Review 61", true),
        ("SHA-256 of the object, IPv6 and IPv4", false),
        ("records NN-L-FIM-009 (High)", false),
        ("NN-L-NET-026 and NN-L-EPG-001/002", false),
        ("x86-64-v2, TLS 1.3, P-256", false),
        ("WAL, W, WebSocket, KW6", false),
        ("R018_KernelModuleLoad", false),
        ("review the diff before 2 runs", false),
        ("nn-admin heartbeat export", false),
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

/// The colour scan before lot 1.7b (lexical, line by line), kept only to
/// show the spellings it missed.
mod lexical {
    use std::collections::BTreeMap;

    use super::support::{production, strip_comments};

    /// The problems the lexical scan finds in `code`.
    pub fn colour_problems(code: &BTreeMap<String, String>) -> Vec<String> {
        let code: BTreeMap<String, String> = code
            .iter()
            .map(|(r, t)| (r.clone(), production(&strip_comments(t))))
            .collect();
        let mut problems = Vec::new();
        for (rel, text) in &code {
            for (n, line) in text.lines().enumerate() {
                let at = format!("{rel}:{}", n + 1);
                if line.contains("is_terminal(")
                    && !line.contains("colour_on(")
                    && !line.contains("\"NO_COLOR\"")
                {
                    problems.push(format!("{at}: a terminal check without NO_COLOR: {line}"));
                }
                let lower = line.to_ascii_lowercase();
                if ["\\x1b", "\\u{1b}", "\\u{001b}", "\\033"]
                    .iter()
                    .any(|e| lower.contains(&format!("{e}[")) || lower.contains(&format!("{e}]")))
                {
                    let colorize = rel == "crates/nn-admin/src/cli.rs"
                        && line.trim() == "format!(\"\\x1b[{sgr}m{s}\\x1b[0m\")";
                    if !colorize {
                        problems.push(format!("{at}: an escape sequence outside colorize: {line}"));
                    }
                }
                if let Some(i) = line.find(".with_ansi(") {
                    let arg = &line[i + ".with_ansi(".len()..];
                    if !arg.starts_with("false)")
                        && !arg.starts_with("nn_model::log_escape::stdout_ansi())")
                    {
                        problems.push(format!("{at}: a colour not from stdout_ansi: {line}"));
                    }
                }
            }
            let mut from = 0;
            while let Some(i) = text[from..].find("tracing_subscriber::fmt()") {
                let start = from + i;
                let end = text[start..].find(';').map_or(text.len(), |j| start + j);
                if !text[start..end].contains(".with_ansi(") {
                    let line = text[..start].lines().count() + 1;
                    problems.push(format!("{rel}:{line}: a fmt layer with the default colour"));
                }
                from = end;
            }
        }
        problems
    }
}
