//! Lab PR 256 — the agents the tests start keep their state in the test's
//! directory.
//!
//! Lot 255 found the installed agent's boot check reporting
//! `chain_verify_failed` on every lab guest and in the KVM CI: the
//! privileged suites, run as root where an agent is installed, started
//! agents with a signing key of their own but without a detection log (and,
//! for some, without any of the agent's chains), so those agents appended
//! rows under their key to the installed agent's chains in
//! `/var/lib/northnarrow`; three fixtures passed neither key nor audit log,
//! and signed the installed agent's audit chain with the installed key.
//!
//! `agent/tests/common/agent_state.rs` is the one way a test starts an
//! agent: `AgentState` gives every path flag the agent writes a file in the
//! test's directory, `InstalledAgent::command` starts the agent with all of
//! them. This test holds the tree to it:
//!
//! 1. the helper classifies every path flag of the agent's command line
//!    (each `PathBuf` field of `Cli`, `agent/src/boot/cli.rs`): `STATE_FLAGS`
//!    (written, or the agent's identity: the helper passes them) or
//!    `INPUT_FLAGS` (read), each once — a new flag fails until it is
//!    classified; and the helper passes every one of `STATE_FLAGS`;
//! 2. no test starts an agent but through the helper: under
//!    `agent/tests` and `watchdog/tests` no `Command::new(…)` names the
//!    agent as its program or as the command of `sudo`/`env` (the program
//!    is an expression with `agent` in it: `&installed_agent.path`,
//!    `agent_exe`, `self.agent`, `InstalledAgent::agent_exe()`), and the
//!    agent's binary is reached only through the helper
//!    (`CARGO_BIN_EXE_northnarrow-agent`, `join("northnarrow-agent")`),
//!    [`BINARY_SITES`] aside;
//! 3. no test names one of the agent's state flags itself (those nn-admin
//!    and the watchdog do not take too): the helper does;
//! 4. a test that names the agent's host paths (the pin root,
//!    `/etc/northnarrow`, `/var/lib/northnarrow`, `/run/northnarrow`, the
//!    honeypot list) says why, in [`HOST_PATH_USERS`]; a file listed there
//!    that no longer names one fails too;
//! 5. the agent's tests and the watchdog's use the same file.
//!
//! Each rule is shown failing on a planted violation. The scan is lexical:
//! comments are blanked first, strings kept; a builder split over
//! statements (`let mut c = Command::new("sudo"); c.arg(…)`) is followed
//! through the variable's later `.arg`/`.args` calls in the same function.

mod support;

use std::collections::BTreeSet;
use std::fs;

use support::{repo_root, rs_files};

const HELPER: &str = "agent/tests/common/agent_state.rs";
const COMMON: &str = "agent/tests/common/mod.rs";
const WATCHDOG_SUITE: &str = "watchdog/tests/privileged_e2e.rs";
// R11a (lab PR 261): the agent's command line is its `boot::cli` (it was
// `main.rs`'s).
const AGENT_MAIN: &str = "agent/src/boot/cli.rs";
// R10 (lab PR 259): nn-admin's command line is nn-admin's (`cli`); the
// agent package's `bin/nn_admin.rs` is the shim that runs it.
const NN_ADMIN_MAIN: &str = "crates/nn-admin/src/cli.rs";
const WATCHDOG_CLI: &str = "watchdog/src/lib.rs";
const TEST_TREES: &[&str] = &["agent/tests", "watchdog/tests"];

/// Ways to the agent's binary outside the helper, and why each starts no
/// agent that writes state.
const BINARY_SITES: &[(&str, &str)] = &[(
    "agent/tests/build_features_cli.rs",
    "`northnarrow-agent --build-features` prints the build's lab features and exits before it \
     opens any path, loads any eBPF or needs root: the ordinary test job runs it",
)];

/// The files under the test trees that name the agent's host paths, and
/// why. The agent has no flag for these paths (the helper's `HOST_PATHS`);
/// none of them is an evidence chain.
const HOST_PATH_USERS: &[(&str, &str)] = &[
    (
        "agent/tests/common/mod.rs",
        "the pinned PROTECTED_PIDS map, which a fixture's teardown evicts its agent from",
    ),
    (
        "agent/tests/boot_refusal_privileged_e2e.rs",
        "the pin root and the pinned PROTECTED_PIDS, read before and after a refused start \
         (lab PR 262): it pinned nothing and left no registration; nothing there is written",
    ),
    (
        "agent/tests/privileged_map_pin.rs",
        "the pin root is what it tests: the pins outlive the agent and its restart reuses them",
    ),
    (
        "agent/tests/fs_deny_privileged_e2e.rs",
        "the denies of the agent's fixed directories (/etc/northnarrow, \
         /var/lib/northnarrow/detections, the pin root): it creates and removes its own \
         .nn-e2e-152-* entries there, never a file of the installed agent",
    ),
    (
        "agent/tests/honeypot_tamper_e2e.rs",
        "the baits are fixed paths under /etc, /var/lib and /run/northnarrow: \
         RealBaitGuard refuses a host that is not disposable or where an agent runs, and puts \
         every bait back",
    ),
    (
        "agent/tests/canary_privileged_e2e.rs",
        "purges the pin root before its agent starts",
    ),
    (
        "agent/tests/detection_rules_at_scale_privileged_e2e.rs",
        "purges the pin root before its agent starts",
    ),
    (
        "agent/tests/net_privileged_e2e.rs",
        "purges the pin root before its agent starts",
    ),
    (
        "agent/tests/fim_privileged_e2e.rs",
        "purges the pin root before its agent starts",
    ),
    (
        "agent/tests/response_privileged_e2e.rs",
        "purges the pin root before its agent starts",
    ),
    (
        "agent/tests/chain_format_pin.rs",
        "data: the paths inside the pinned audit rows; nothing on the host is opened",
    ),
    (
        "watchdog/tests/privileged_e2e.rs",
        "the pin root the agent and the watchdog share (--bpffs-root), purged before and after \
         each test",
    ),
    (
        "watchdog/tests/systemd_units.rs",
        "data: the paths the shipped units name; nothing on the host is opened",
    ),
];

/// What names one of the agent's host paths in a test's code.
const HOST_PATH_LITERALS: &[&str] = &[
    "/sys/fs/bpf/northnarrow",
    "/etc/northnarrow",
    "/var/lib/northnarrow",
    "/run/northnarrow",
];
const HOST_PATH_NAMES: &[&str] = &[
    "DEFAULT_BPFFS_ROOT",
    "HONEYPOT_PATHS",
    "STATE_DIR",
    "CONFIG_DIR",
];

/// The programs whose first operand is the command they run.
const RUNNERS: &[&str] = &[
    "\"sudo\"",
    "\"/usr/bin/sudo\"",
    "REAL_SUDO",
    "common::REAL_SUDO",
    "SUDO",
    "\"env\"",
];

fn read(rel: &str) -> String {
    let path = repo_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// The `.rs` files of the test trees, repository-relative, with their text.
fn test_sources() -> Vec<(String, String)> {
    let root = repo_root();
    let mut files = Vec::new();
    for tree in TEST_TREES {
        rs_files(&root.join(tree), &mut files);
    }
    files
        .into_iter()
        .map(|f| {
            let rel = f
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            let text = fs::read_to_string(&f).unwrap();
            (rel, text)
        })
        .collect()
}

// ── lexing ────────────────────────────────────────────────────────────────

/// `src` with its comments blanked (newlines kept, so line numbers hold);
/// string, raw string and char literals kept as they are.
fn strip_comments(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    let blank = |c: u8| if c == b'\n' { b'\n' } else { b' ' };
    let ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    while i < b.len() {
        let c = b[i];
        if c == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                out.push(b' ');
                i += 1;
            }
        } else if c == b'/' && b.get(i + 1) == Some(&b'*') {
            let mut depth = 0usize;
            while i < b.len() {
                if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                    depth += 1;
                    out.extend_from_slice(b"  ");
                    i += 2;
                } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                    depth -= 1;
                    out.extend_from_slice(b"  ");
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    out.push(blank(b[i]));
                    i += 1;
                }
            }
        } else if c == b'r'
            && (i == 0 || !ident(b[i - 1]))
            && matches!(b.get(i + 1), Some(b'"') | Some(b'#'))
        {
            // r"…", r#"…"#
            let mut j = i + 1;
            while b.get(j) == Some(&b'#') {
                j += 1;
            }
            if b.get(j) != Some(&b'"') {
                out.push(c);
                i += 1;
                continue;
            }
            let hashes = j - i - 1;
            let mut close = vec![b'"'];
            close.extend(std::iter::repeat_n(b'#', hashes));
            let end = b[j + 1..]
                .windows(close.len())
                .position(|w| w == close.as_slice())
                .map_or(b.len(), |p| j + 1 + p + close.len());
            out.extend_from_slice(&b[i..end]);
            i = end;
        } else if c == b'"' {
            let start = i;
            i += 1;
            while i < b.len() && b[i] != b'"' {
                if b[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            i = (i + 1).min(b.len());
            out.extend_from_slice(&b[start..i]);
        } else if c == b'\'' {
            // A char literal ('x', '\n', '\u{1b}') or a lifetime ('a).
            if b.get(i + 1) == Some(&b'\\') {
                let start = i;
                i += 2;
                while i < b.len() && b[i] != b'\'' {
                    i += 1;
                }
                i = (i + 1).min(b.len());
                out.extend_from_slice(&b[start..i]);
            } else {
                // `i` follows ASCII bytes only, so `i + 1` is a char boundary.
                let len = src[i + 1..].chars().next().map_or(1, char::len_utf8);
                if b.get(i + 1 + len) == Some(&b'\'') {
                    out.extend_from_slice(&b[i..i + 2 + len]);
                    i += 2 + len;
                } else {
                    out.push(c);
                    i += 1;
                }
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    String::from_utf8(out).expect("blanking keeps UTF-8")
}

/// The contents of the string literals of `code` (comments already
/// blanked), with the line each starts on.
fn string_literals(code: &str) -> Vec<(usize, String)> {
    let b = code.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let line_of = |at: usize| code[..at].matches('\n').count() + 1;
    while i < b.len() {
        if b[i] == b'\'' {
            // skip a char literal so '"' does not open a string
            if b.get(i + 2) == Some(&b'\'') {
                i += 3;
                continue;
            }
            if b.get(i + 1) == Some(&b'\\') {
                i += 2;
                while i < b.len() && b[i] != b'\'' {
                    i += 1;
                }
                i += 1;
                continue;
            }
        }
        if b[i] == b'"' {
            let start = i;
            i += 1;
            while i < b.len() && b[i] != b'"' {
                if b[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            out.push((line_of(start), code[start + 1..i.min(b.len())].to_string()));
        }
        i += 1;
    }
    out
}

/// The text from `open` (a `(`, `[` or `{`) to its match, both included.
fn balanced(code: &str, open: usize) -> &str {
    let b = code.as_bytes();
    let (o, c) = match b[open] {
        b'(' => (b'(', b')'),
        b'[' => (b'[', b']'),
        _ => (b'{', b'}'),
    };
    let mut depth = 0usize;
    let mut i = open;
    while i < b.len() {
        match b[i] {
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            x if x == o => depth += 1,
            x if x == c => {
                depth -= 1;
                if depth == 0 {
                    return &code[open..=i];
                }
            }
            _ => {}
        }
        i += 1;
    }
    &code[open..]
}

/// The top-level comma-separated items of a `(…)` or `[…]` text.
fn items(group: &str) -> Vec<String> {
    let inner = &group[1..group.len().saturating_sub(1)];
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    let mut in_str = false;
    let mut prev = '\0';
    for ch in inner.chars() {
        if in_str {
            cur.push(ch);
            if ch == '"' && prev != '\\' {
                in_str = false;
            }
            prev = if prev == '\\' && ch == '\\' { '\0' } else { ch };
            continue;
        }
        match ch {
            '"' => {
                in_str = true;
                cur.push(ch);
            }
            '(' | '[' | '{' => {
                depth += 1;
                cur.push(ch);
            }
            ')' | ']' | '}' => {
                depth -= 1;
                cur.push(ch);
            }
            ',' if depth == 0 => {
                out.push(cur.trim().to_string());
                cur.clear();
            }
            _ => cur.push(ch),
        }
        prev = ch;
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

/// The `.name(args)` calls chained at `at` (just after a call's closing
/// parenthesis): `(name, args)` in order.
fn chained_calls(code: &str, mut at: usize) -> Vec<(String, String)> {
    let b = code.as_bytes();
    let mut out = Vec::new();
    loop {
        while at < b.len() && b[at].is_ascii_whitespace() {
            at += 1;
        }
        if b.get(at) != Some(&b'.') {
            return out;
        }
        at += 1;
        let start = at;
        while at < b.len() && (b[at].is_ascii_alphanumeric() || b[at] == b'_') {
            at += 1;
        }
        let name = code[start..at].to_string();
        // turbofish or whitespace before the arguments
        while at < b.len() && b[at].is_ascii_whitespace() {
            at += 1;
        }
        if b.get(at) != Some(&b'(') {
            // a field access (`.0`, `.path`) ends the call chain
            return out;
        }
        let args = balanced(code, at);
        at += args.len();
        out.push((name, args.to_string()));
    }
}

/// One `Command::new(…)` of a test: the program expression and the
/// operands its `.arg`/`.args` calls add, in order.
#[derive(Debug)]
struct Spawn {
    line: usize,
    program: String,
    operands: Vec<String>,
}

/// Every `Command::new(…)` of `code` (comments blanked). The operands are
/// those of the call chain; when the builder is bound (`let mut c =
/// Command::new(…);`), also those of `c.arg(…)`/`c.args(…)` until the end
/// of the function.
fn spawns(code: &str) -> Vec<Spawn> {
    let mut out = Vec::new();
    for (at, _) in code.match_indices("Command::new(") {
        let open = at + "Command::new".len();
        let group = balanced(code, open);
        let program = group[1..group.len() - 1].trim().to_string();
        let mut operands = Vec::new();
        let mut add = |calls: Vec<(String, String)>| {
            for (name, args) in calls {
                match name.as_str() {
                    "arg" => operands.push(args[1..args.len() - 1].trim().to_string()),
                    "args" => {
                        let inner = items(&args);
                        let one = inner.first().cloned().unwrap_or_default();
                        if one.starts_with('[') {
                            operands.extend(items(&one));
                        } else if one.starts_with("&[") {
                            operands.extend(items(&one[1..]));
                        } else {
                            operands.push(one);
                        }
                    }
                    _ => {}
                }
            }
        };
        add(chained_calls(code, open + group.len()));
        // `let [mut] <var> = Command::new(…);`
        let line_start = code[..at].rfind('\n').map_or(0, |n| n + 1);
        let head = code[line_start..at].trim();
        if let Some(var) = head
            .strip_prefix("let mut ")
            .or_else(|| head.strip_prefix("let "))
            .and_then(|s| s.strip_suffix('='))
            .map(|s| s.trim().split(':').next().unwrap().trim().to_string())
        {
            let rest_start = open + group.len();
            let end = ["\nfn ", "\n    fn "]
                .iter()
                .filter_map(|f| code[rest_start..].find(f))
                .min()
                .map_or(code.len(), |e| rest_start + e);
            let body = &code[rest_start..end];
            let pat = format!("{var}.");
            let mut from = 0;
            while let Some(p) = body[from..].find(&pat) {
                let abs = rest_start + from + p;
                let before = code.as_bytes()[abs.saturating_sub(1)];
                if !(before.is_ascii_alphanumeric() || before == b'_' || before == b'.') {
                    add(chained_calls(code, abs + var.len()));
                }
                from += p + pat.len();
            }
        }
        out.push(Spawn {
            line: code[..at].matches('\n').count() + 1,
            program,
            operands,
        });
    }
    out
}

/// The command a spawn runs: its program, or for `sudo`/`env` the first
/// operand that is neither an option, `env`, nor a `NAME=value`.
fn command_of(s: &Spawn) -> String {
    if !RUNNERS.contains(&s.program.as_str()) {
        return s.program.clone();
    }
    for op in &s.operands {
        let unquoted = op.trim_matches('"');
        let assignment = op.contains("ASSIGNMENT")
            || (op.starts_with('"') && unquoted.contains('='))
            || (op.starts_with("format!(") && op.contains('='));
        if op.starts_with("\"-") || unquoted == "env" || assignment {
            continue;
        }
        return op.clone();
    }
    String::new()
}

/// An expression that names the agent: `agent` in it, the crate's own
/// path (`northnarrow_agent::`) aside.
fn names_the_agent(expr: &str) -> bool {
    expr.to_ascii_lowercase()
        .replace("northnarrow_agent::", "")
        .contains("agent")
}

// ── the checks, as functions of the sources (the planted tests feed them) ──

/// Rule 1: `Cli`'s path flags, from `main_rs`.
fn cli_path_flags(main_rs: &str) -> Vec<String> {
    let code = strip_comments(main_rs);
    let start = code
        .find("struct Cli {")
        .expect("agent/src/boot/cli.rs: struct Cli");
    let body = balanced(&code, start + "struct Cli ".len());
    let mut flags = Vec::new();
    let mut attrs = String::new();
    let mut field = String::new();
    for line in body.lines() {
        let t = line.trim();
        if t.starts_with("#[") || !attrs.is_empty() && !attrs.trim_end().ends_with(")]") {
            attrs.push_str(t);
            attrs.push(' ');
            continue;
        }
        if t.is_empty() {
            continue;
        }
        field.push_str(t);
        field.push(' ');
        if !t.ends_with(',') {
            continue;
        }
        let (name, ty) = field.split_once(':').unwrap_or(("", ""));
        if ty.contains("PathBuf") {
            let name = name
                .trim()
                .trim_start_matches("pub(crate) ")
                .trim_start_matches("pub ")
                .trim();
            let flag = attrs
                .split("long = \"")
                .nth(1)
                .and_then(|s| s.split('"').next())
                .map(str::to_string)
                .unwrap_or_else(|| name.replace('_', "-"));
            flags.push(format!("--{flag}"));
        }
        attrs.clear();
        field.clear();
    }
    flags
}

/// The helper's `STATE_FLAGS` (each `flag: "--…"` of the list) and
/// `INPUT_FLAGS` (the first string of each pair).
fn helper_flags(helper: &str) -> (Vec<String>, Vec<String>) {
    let code = strip_comments(helper);
    let list = |name: &str| -> String {
        let at = code
            .find(&format!("pub const {name}"))
            .unwrap_or_else(|| panic!("{HELPER}: no `pub const {name}`"));
        let open = at + code[at..].find("= &[").expect("a list") + "= &".len();
        balanced(&code, open).to_string()
    };
    let state = list("STATE_FLAGS")
        .split("flag: \"")
        .skip(1)
        .map(|s| s.split('"').next().unwrap().to_string())
        .collect();
    let input = items(&list("INPUT_FLAGS"))
        .iter()
        .filter_map(|pair| {
            let inner = items(pair);
            inner.first().map(|s| s.trim_matches('"').to_string())
        })
        .collect();
    (state, input)
}

/// Rule 1's findings.
fn flag_classification(main_rs: &str, helper: &str) -> Vec<String> {
    let mut bad = Vec::new();
    let cli = cli_path_flags(main_rs);
    assert!(
        cli.len() >= 30,
        "{AGENT_MAIN}: only {} path flags read",
        cli.len()
    );
    let (state, input) = helper_flags(helper);
    let mut seen = BTreeSet::new();
    for f in state.iter().chain(&input) {
        if !seen.insert(f.clone()) {
            bad.push(format!("{HELPER}: {f} classified twice"));
        }
        if !cli.contains(f) {
            bad.push(format!(
                "{HELPER}: {f} is not a path flag of the agent ({AGENT_MAIN}, Cli)"
            ));
        }
    }
    for f in &cli {
        if !seen.contains(f) {
            bad.push(format!(
                "{AGENT_MAIN}: the agent's path flag {f} is in neither STATE_FLAGS nor \
                 INPUT_FLAGS of {HELPER}: a file it writes goes in the test's directory \
                 (STATE_FLAGS), one it only reads is an input"
            ));
        }
    }
    // The helper passes every state flag: `args` walks STATE_FLAGS, and the
    // one constructor of the agent's command calls it.
    let code = strip_comments(helper);
    let body_of = |sig: &str| -> String {
        let at = code
            .find(sig)
            .unwrap_or_else(|| panic!("{HELPER}: no `{sig}`"));
        let open = at + code[at..].find('{').unwrap();
        balanced(&code, open).to_string()
    };
    if !body_of("pub fn args(&self)").contains("STATE_FLAGS") {
        bad.push(format!(
            "{HELPER}: AgentState::args does not walk STATE_FLAGS"
        ));
    }
    if !body_of("pub fn command(").contains("state.args()") {
        bad.push(format!(
            "{HELPER}: InstalledAgent::command does not pass AgentState::args"
        ));
    }
    bad
}

/// Rule 2's findings in one test file.
fn agent_spawns(rel: &str, text: &str) -> Vec<String> {
    if rel == HELPER || BINARY_SITES.iter().any(|(f, _)| *f == rel) {
        return Vec::new();
    }
    let code = strip_comments(text);
    let mut bad = Vec::new();
    for s in spawns(&code) {
        let cmd = command_of(&s);
        if names_the_agent(&cmd) {
            bad.push(format!(
                "{rel}:{}: starts the agent itself (`Command::new({})`, command `{cmd}`): \
                 use common::agent_state::InstalledAgent::command, which puts every file the \
                 agent writes in the test's directory",
                s.line, s.program
            ));
        }
    }
    for needle in [
        "CARGO_BIN_EXE_northnarrow-agent",
        "join(\"northnarrow-agent\")",
    ] {
        for (at, _) in code.match_indices(needle) {
            bad.push(format!(
                "{rel}:{}: reaches the agent's binary (`{needle}`) outside {HELPER}: \
                 InstalledAgent::install",
                code[..at].matches('\n').count() + 1
            ));
        }
    }
    bad
}

/// The agent's state flags that nn-admin and the watchdog do not take
/// (the shared names, `--agent-id-file` …, are theirs too).
fn exclusive_state_flags(helper: &str, nn_admin: &str, watchdog: &str) -> Vec<String> {
    let (state, _) = helper_flags(helper);
    state
        .into_iter()
        .filter(|f| {
            let name = &f[2..];
            let quoted = format!("\"{name}\"");
            let field = name.replace('-', "_");
            ![nn_admin, watchdog].iter().any(|src| {
                src.contains(&format!("long = {quoted}"))
                    || src.contains(&format!("#[arg(long)]\n    pub {field}:"))
                    || src.contains(&format!("#[arg(long)]\n        {field}:"))
            })
        })
        .collect()
}

/// Rule 3's findings in one test file.
fn state_flag_uses(rel: &str, text: &str, exclusive: &[String]) -> Vec<String> {
    if rel == HELPER {
        return Vec::new();
    }
    let code = strip_comments(text);
    let mut bad = Vec::new();
    for (line, lit) in string_literals(&code) {
        if exclusive.contains(&lit) {
            bad.push(format!(
                "{rel}:{line}: names the agent's state flag {lit}: the helper passes every \
                 one (common::agent_state::AgentState), in the test's directory"
            ));
        }
    }
    bad
}

/// Whether a test file's code names one of the agent's host paths.
fn names_host_paths(text: &str) -> Vec<String> {
    let code = strip_comments(text);
    let mut found = Vec::new();
    for (line, lit) in string_literals(&code) {
        if let Some(p) = HOST_PATH_LITERALS.iter().find(|p| lit.contains(**p)) {
            found.push(format!("{line}: \"{p}…\""));
        }
    }
    for name in HOST_PATH_NAMES {
        for (at, _) in code.match_indices(name) {
            let b = code.as_bytes();
            let before = at.checked_sub(1).map(|i| b[i]);
            let after = b.get(at + name.len()).copied();
            let word = |c: Option<u8>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == b'_');
            if !word(before) && !word(after) {
                found.push(format!("{}: {name}", code[..at].matches('\n').count() + 1));
            }
        }
    }
    found
}

/// Rule 4's findings over the test sources.
fn host_path_users(sources: &[(String, String)], listed: &[(&str, &str)]) -> Vec<String> {
    let mut bad = Vec::new();
    for (rel, text) in sources {
        if rel == HELPER {
            continue;
        }
        let found = names_host_paths(text);
        let entry = listed.iter().find(|(f, _)| f == rel);
        match (found.is_empty(), entry) {
            (false, None) => bad.push(format!(
                "{rel}: names the agent's host paths ({}) without saying why: add it to \
                 HOST_PATH_USERS with its reason (an agent's own files go in the test's \
                 directory: common::agent_state::AgentState)",
                found.join(", ")
            )),
            (true, Some(_)) => bad.push(format!(
                "{rel}: listed in HOST_PATH_USERS but names no host path any more: remove it"
            )),
            _ => {}
        }
    }
    for (f, why) in listed {
        if !sources.iter().any(|(rel, _)| rel == f) {
            bad.push(format!("HOST_PATH_USERS: {f} does not exist"));
        }
        if why.trim().is_empty() {
            bad.push(format!("HOST_PATH_USERS: {f} has no reason"));
        }
    }
    bad
}

fn assert_none(what: &str, bad: Vec<String>) {
    assert!(bad.is_empty(), "{what}:\n{}", bad.join("\n"));
}

// ── the tree ──────────────────────────────────────────────────────────────

#[test]
fn the_helper_classifies_every_path_flag_of_the_agent() {
    assert_none(
        "the agent's path flags and the helper",
        flag_classification(&read(AGENT_MAIN), &read(HELPER)),
    );
}

#[test]
fn no_test_starts_an_agent_but_through_the_helper() {
    let sources = test_sources();
    assert!(
        sources.len() >= 20,
        "only {} test sources found",
        sources.len()
    );
    let mut bad = Vec::new();
    let mut agent_tests = 0;
    for (rel, text) in &sources {
        bad.extend(agent_spawns(rel, text));
        if text.contains(".command(&") && text.contains("Launch::") {
            agent_tests += 1;
        }
    }
    assert_none("agents started outside the helper", bad);
    // The scan sees the suites it guards: each of them starts its agents
    // through the helper.
    assert!(
        agent_tests >= 10,
        "only {agent_tests} test files start an agent through the helper"
    );
    for (f, why) in BINARY_SITES {
        let text = read(f);
        assert!(
            text.contains("CARGO_BIN_EXE_northnarrow-agent"),
            "BINARY_SITES: {f} no longer names the agent's binary ({why}): remove it"
        );
    }
}

#[test]
fn no_test_names_the_agents_state_flags() {
    let exclusive = exclusive_state_flags(&read(HELPER), &read(NN_ADMIN_MAIN), &read(WATCHDOG_CLI));
    // The names nn-admin and the watchdog take as well stay out of the
    // rule; the others are the agent's own.
    for shared in ["--agent-id-file", "--admin-pub", "--admin-socket"] {
        assert!(!exclusive.iter().any(|f| f == shared), "{shared}");
    }
    assert!(
        exclusive.len() >= 12 && exclusive.iter().any(|f| f == "--detections-file"),
        "{exclusive:?}"
    );
    let mut bad = Vec::new();
    for (rel, text) in test_sources() {
        bad.extend(state_flag_uses(&rel, &text, &exclusive));
    }
    assert_none("state flags named outside the helper", bad);
}

#[test]
fn the_tests_that_use_host_paths_say_why() {
    assert_none(
        "host paths",
        host_path_users(&test_sources(), HOST_PATH_USERS),
    );
}

#[test]
fn the_agent_and_watchdog_tests_share_the_helper() {
    assert!(
        read(COMMON).contains("pub mod agent_state;"),
        "{COMMON}: `pub mod agent_state;`"
    );
    let wd: String = strip_comments(&read(WATCHDOG_SUITE))
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    assert!(
        wd.contains(&format!(
            "include!(concat!(env!(\"NN_REPO_ROOT\"),\"/{HELPER}\"));"
        )),
        "{WATCHDOG_SUITE}: includes {HELPER}"
    );
    // `include!` takes items only: no inner attribute or doc in the helper.
    let code = strip_comments(&read(HELPER));
    assert!(!code.contains("#!["), "{HELPER}: an inner attribute");
    assert!(
        !read(HELPER)
            .lines()
            .any(|l| l.trim_start().starts_with("//!")),
        "{HELPER}: an inner doc comment"
    );
}

// ── planted violations: each rule fails on what it is meant to catch ─────

/// The planted sources' name (not a path of the repository:
/// `path_liveness.rs` holds the xtask tests' literal paths to the tree).
const PLANTED: &str = "planted/suite.rs";

/// What the three fixtures of lot 255 looked like: a signing key of their
/// own, the host's detection log.
const PLANTED_SUDO_SPAWN: &str = r#"
fn setup() {
    let installed_agent = install_to_priv_bin(Path::new(agent_bin()));
    let child = Command::new(REAL_SUDO)
        .arg("env")
        .arg(common::OWN_DEFAULT_LISTS_ASSIGNMENT)
        .arg(&installed_agent.path)
        .arg("--signing-key-file")
        .arg(dir.join("agent.sig.key"))
        .spawn();
}
"#;

#[test]
fn a_planted_spawn_outside_the_helper_fails() {
    let bad = agent_spawns(PLANTED, PLANTED_SUDO_SPAWN);
    assert_eq!(bad.len(), 1, "{bad:?}");
    assert!(
        bad[0].contains(&format!("{PLANTED}:4: starts the agent itself")),
        "{bad:?}"
    );
    // the build's binary run directly
    let direct = "fn t() {\n    let out = Command::new(env!(\"CARGO_BIN_EXE_northnarrow-agent\"))\n        .arg(\"--admin-socket\").spawn();\n}\n";
    let bad = agent_spawns(PLANTED, direct);
    assert_eq!(bad.len(), 2, "the spawn and the binary: {bad:?}");
    // a builder bound to a variable (the shape of the old GuardFixture)
    let split = "fn spawn(&self) {\n    let mut cmd = Command::new(\"sudo\");\n    cmd.arg(\"env\").arg(\"NO_COLOR=1\");\n    if enforce {\n        cmd.arg(format!(\"{}=1\", ENFORCE_ENV));\n    }\n    cmd.arg(&self.agent).arg(\"--detect-only\");\n}\n\nfn other() {\n    let x = 1;\n}\n";
    let bad = agent_spawns(PLANTED, split);
    assert_eq!(bad.len(), 1, "{bad:?}");
    // the helper's own accessor, used to start it
    let exe = "fn t(a: &InstalledAgent) {\n    Command::new(a.agent_exe()).spawn();\n}\n";
    assert_eq!(agent_spawns(PLANTED, exe).len(), 1);
    // the watchdog's binary and the helper's command are not agent spawns;
    // nor is a comment, nor sudo running bpftool
    let fine = "fn t() {\n    // Command::new(&installed_agent.path)\n    let c = agent.command(&state, Launch::Sudo, &[]).arg(\"--combat-rules\");\n    Command::new(\"sudo\").arg(self.watchdog_priv_path()).arg(\"--agent-bin\").arg(self.agent_priv_path());\n    Command::new(\"sudo\").args([\"bpftool\", \"map\", \"delete\"]).arg(agent_pid.to_string());\n}\n";
    assert_eq!(agent_spawns(PLANTED, fine), Vec::<String>::new());
    // and the allowlisted site stays allowed
    assert!(agent_spawns(BINARY_SITES[0].0, direct).is_empty());
}

#[test]
fn a_planted_state_flag_outside_the_helper_fails() {
    let exclusive = exclusive_state_flags(&read(HELPER), &read(NN_ADMIN_MAIN), &read(WATCHDOG_CLI));
    let bad = state_flag_uses(PLANTED, PLANTED_SUDO_SPAWN, &exclusive);
    assert_eq!(bad.len(), 1, "{bad:?}");
    assert!(bad[0].contains("--signing-key-file"), "{bad:?}");
    // nn-admin's flags of the same name are not the agent's
    let admin = "fn t() {\n    Command::new(nn).args([\"unlock\", \"--agent-id-file\", id, \"--socket\", s]);\n    // --detections-file in a comment\n}\n";
    assert!(state_flag_uses(PLANTED, admin, &exclusive).is_empty());
}

#[test]
fn a_planted_unclassified_path_flag_fails() {
    let main_rs = read(AGENT_MAIN).replacen(
        "struct Cli {",
        "struct Cli {\n    #[arg(long = \"quarantine-dir\", value_name = \"PATH\")]\n    quarantine_dir: PathBuf,\n",
        1,
    );
    let bad = flag_classification(&main_rs, &read(HELPER));
    assert_eq!(bad.len(), 1, "{bad:?}");
    assert!(bad[0].contains("--quarantine-dir"), "{bad:?}");
    // a helper that stopped passing its state flags
    let helper = read(HELPER).replacen("cmd.args(state.args());", "", 1);
    let bad = flag_classification(&read(AGENT_MAIN), &helper);
    assert_eq!(bad.len(), 1, "{bad:?}");
    // a flag classified twice
    let helper = read(HELPER).replacen(
        "(\"--btf-check\"",
        "(\"--detections-file\", \"x\"),\n    (\"--btf-check\"",
        1,
    );
    let bad = flag_classification(&read(AGENT_MAIN), &helper);
    assert!(
        bad.iter()
            .any(|b| b.contains("--detections-file classified twice")),
        "{bad:?}"
    );
}

#[test]
fn a_planted_host_path_without_a_reason_fails() {
    let mut sources = test_sources();
    sources.push((
        PLANTED.to_string(),
        "const STATE: &str = \"/var/lib/northnarrow/detections\";\n".to_string(),
    ));
    let bad = host_path_users(&sources, HOST_PATH_USERS);
    assert_eq!(bad.len(), 1, "{bad:?}");
    assert!(bad[0].starts_with(&format!("{PLANTED}: names")), "{bad:?}");
    // a listed file that names none any more
    let mut listed = HOST_PATH_USERS.to_vec();
    listed.push(("agent/tests/journal_fields.rs", "planted"));
    let bad = host_path_users(&test_sources(), &listed);
    assert_eq!(bad.len(), 1, "{bad:?}");
    // a host path in a comment is not a use
    assert!(names_host_paths("// /etc/northnarrow/audit.log\nfn t() {}\n").is_empty());
}

#[test]
fn the_lexer_blanks_comments_and_keeps_strings() {
    let src = "let a = \"// kept\"; // gone \"x\"\nlet b = '\"'; /* gone /* nested */ \"y\" */ \
               let c = \"kept too\";\nlet l: &'static str = \"z\"; let r = r#\"// raw\"#;\n";
    let code = strip_comments(src);
    assert_eq!(code.lines().count(), 3);
    assert!(
        !code.contains("gone") && !code.contains("\"x\"") && !code.contains("\"y\""),
        "{code}"
    );
    assert!(code.contains("r#\"// raw\"#"), "{code}");
    let lits: Vec<String> = string_literals(&code)
        .into_iter()
        .map(|(_, s)| s)
        .take(3)
        .collect();
    assert_eq!(lits, ["// kept", "kept too", "z"]);
}
