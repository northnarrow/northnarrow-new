//! Lot 310 (external bug hunt, edition 1.4: BUG-97, BUG-99, BUG-100, N3):
//! an interpreter's options are read in one place —
//! `crates/nn-core/src/posture/script_args.rs`, one reader over a table per
//! family — and this ratchet keeps it so.
//!
//! Every identity bug of the three hunts in this family (BUG-42, BUG-44,
//! BUG-97, BUG-99, BUG-100, N3) was an argv read by hand: an option with
//! the wrong arity, a spelling the hand-written reader did not know
//! (`-noprofile`, `--eval=`, `-ovi`), the script taken as "the first
//! argument". A new site of that shape fails here until it calls the reader
//! (`runs_of`, `ExecIdentity::of_exec`/`of_spawn`, `inline_program`) or its
//! file is listed in [`KNOWN`] with why it is no interpreter's option read.
//!
//! Lot 310, the independent review of #539 (finding 9): the first ratchet
//! scanned six crates and a fixed list of literals, and seven twins planted
//! in nn-core passed it (`.nth(1)` on a split cmdline, `"--eval="`, `==
//! "-ec"`, `"--require"`, `cmd.get(idx + 1)`). It scans every product crate
//! now ([`support::product_code`]: every `src` tree but xtask's and fuzz's;
//! a file named `tests.rs` only when its parent declares it under
//! `#[cfg(test)]`), and counts ([`count`]):
//!
//! - every string literal that is an option, of any program — a cluster or
//!   a one-hyphen word (`"-c"`, `"-ec"`, `"-norc"`) or a long option
//!   (`"--eval"`, `"--eval="`): a comparison with an argument, or a command
//!   line built;
//! - on a line that names an argv (`argv`, `args`, `cmdline`, `cmd`), a
//!   positional read or search: `.get(`, `.nth(`, `.position(`, `.skip(`;
//!   and an argv indexed (`argv[1]`, `args[i]`) — in code, not in a string.
//!
//! A file's count may not grow above its pin, and a count below it fails
//! until the pin comes down — the table is always the code's.

mod support;

use std::collections::BTreeMap;

use support::{concat_literals, product_code, repo_root, string_literals};

/// The one reader.
const READER: &str = "crates/nn-core/src/posture/script_args.rs";

/// A literal that is an option: `-x`, `-ec`, `-norc` (letters, a hyphen
/// within) or `--name`, `--name=`.
fn is_option_literal(s: &str) -> bool {
    if let Some(long) = s.strip_prefix("--") {
        let name = long.strip_suffix('=').unwrap_or(long);
        return !name.is_empty()
            && name.as_bytes()[0].is_ascii_alphabetic()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    }
    // a cluster (`-c`, `-ec`) or a long option with one hyphen (bash's
    // `-norc`, `-init-file`: BUG-97)
    s.strip_prefix('-').is_some_and(|short| {
        short
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
            && short.bytes().all(|b| b.is_ascii_alphabetic() || b == b'-')
    })
}

/// The names an argument vector goes by.
const ARGV_NAMES: &[&str] = &["argv", "args", "cmdline", "cmd"];

/// `word` at byte `i` of `line` stands alone (no identifier character on
/// either side).
fn alone(line: &str, i: usize, len: usize) -> bool {
    let ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    !line[..i].bytes().last().is_some_and(ident)
        && !line[i + len..].bytes().next().is_some_and(ident)
}

/// A line that names an argument vector.
fn names_an_argv(line: &str) -> bool {
    ARGV_NAMES
        .iter()
        .any(|w| line.match_indices(w).any(|(i, _)| alone(line, i, w.len())))
}

/// The positional reads and searches of an argv, on a line that names one.
const POSITIONAL: &[&str] = &[".get(", ".nth(", ".position(", ".skip("];

/// An argv indexed: `argv[1]`, `args[i]`, `&argv[1..]`.
fn indexings(line: &str) -> usize {
    ARGV_NAMES
        .iter()
        .map(|w| {
            line.match_indices(&format!("{w}["))
                .filter(|(i, _)| alone(line, *i, w.len()))
                .count()
        })
        .sum()
}

/// `text` with every string literal's contents blanked: a positional read
/// is code, not a message.
fn without_strings(text: &str) -> String {
    let mut out = text.to_string();
    let mut from = 0;
    for lit in string_literals(text) {
        if lit.is_empty() {
            continue;
        }
        if let Some(at) = out[from..].find(lit.as_str()) {
            let at = from + at;
            out.replace_range(at..at + lit.len(), &" ".repeat(lit.len()));
            from = at + lit.len();
        }
    }
    out
}

/// A command line (or an environment) split on its NULs by hand
/// (`/proc/<pid>/cmdline`, `/proc/<pid>/environ`, an exec record's argv
/// blob): a `split(|…| … == 0)` closure, or a NUL separator.
fn nul_splits(line: &str) -> usize {
    let closure = line.contains("split(|") && (line.contains("== 0") || line.contains("== b'\\0'"));
    let separator = ["split(b'\\0')", "split('\\0')", "split(\"\\0\")"]
        .iter()
        .map(|p| line.matches(p).count())
        .sum::<usize>();
    usize::from(closure) + separator
}

/// A file that holds a command line: it names `argv` or `cmdline`.
fn holds_a_command_line(code: &str) -> bool {
    ["argv", "cmdline"].iter().any(|w| {
        code.lines()
            .any(|l| l.match_indices(w).any(|(i, _)| alone(l, i, w.len())))
    })
}

/// In a file that holds a command line ([`holds_a_command_line`]): a
/// positional read of any value (`.nth(`, `.skip(`) — the argv renamed
/// (`let words = argv; words.iter().nth(1)`, the re-check of #539) — and
/// an option told by its hyphen by hand.
const IN_ARGV_FILES: &[&str] = &[".nth(", ".skip(", "strip_prefix('-')", "starts_with('-')"];

/// The same with a string literal, read in the text as written (the code
/// has its strings blanked): a hyphen tested, an option's name built.
const IN_ARGV_FILES_LITERAL: &[&str] = &["strip_prefix(\"-", "starts_with(\"-", "concat!(\"-"];

/// The sites of `text`: option literals, positional reads and indexings
/// of an argv on a line that names one, NUL splits, and, in a file that
/// holds a command line, [`IN_ARGV_FILES`]'s forms on any line.
fn count(text: &str) -> usize {
    sites(text).len()
}

/// Each site of `text`, described.
fn sites(text: &str) -> Vec<String> {
    let mut out: Vec<String> = string_literals(text)
        .into_iter()
        .chain(concat_literals(text))
        .filter(|l| is_option_literal(l))
        .map(|l| format!("literal {l:?}"))
        .collect();
    let code = without_strings(text);
    // (a `"cmdline"` read counts: the raw text)
    let argv_file = holds_a_command_line(text);
    for l in code.lines() {
        let t = l.trim();
        if names_an_argv(l) {
            for p in POSITIONAL {
                for _ in 0..l.matches(p).count() {
                    out.push(format!("argv line {t}"));
                }
            }
        }
        for _ in 0..indexings(l) {
            out.push(format!("indexed {t}"));
        }
        for _ in 0..nul_splits(l) {
            out.push(format!("NUL split {t}"));
        }
        if argv_file {
            for p in IN_ARGV_FILES {
                // a positional read on an argv line is counted above
                if names_an_argv(l) && POSITIONAL.contains(p) {
                    continue;
                }
                for _ in 0..l.matches(p).count() {
                    out.push(format!("in an argv file {t}"));
                }
            }
        }
    }
    if argv_file {
        for l in text.lines() {
            for p in IN_ARGV_FILES_LITERAL {
                for _ in 0..l.matches(p).count() {
                    out.push(format!("in an argv file {}", l.trim()));
                }
            }
        }
    }
    out
}

/// The files that hold sites: how many, and why none is an interpreter's
/// option read.
const KNOWN: &[(&str, usize, &str)] = &[
    (
        "crates/nn-core/src/impair/mod.rs",
        72,
        "the option tables of the system tools a security tool is switched off with — pkill's, \
         killall's, systemctl's, service's, iptables' and firewall-cmd's (`pattern_args`, \
         `service_targets`, `switches_off`, `kill_signal_is_probe`) and their arguments after the \
         program: their own options, not an interpreter's (the external bug hunt's lot 7 gives \
         them a reader of their own) \
         — and those tools' operands told from their options by the hyphen, a `/proc` stat \
         field (`.nth(19)`)",
    ),
    (
        "crates/nn-core/src/decision/rules/r013_namespace_escape_tooling.rs",
        7,
        "nsenter's, unshare's and a container runtime's options (`-m`, `--mount`, `-t`, \
         `--privileged`): no interpreter's",
    ),
    (
        "crates/nn-core/src/decision/rules/r011_kernel_module_tooling.rs",
        1,
        "an exact argv, `sh -c /bin/true` (a modprobe.d directive's `install x /bin/true`): three \
         words, every other argv is judged — no option read, and the reader would accept more \
         (`sh -i -c /bin/true` reads a startup file)",
    ),
    (
        "crates/nn-core/src/decision/rules/kmod_invocation.rs",
        14,
        "kmod's own options and arguments (`--help`, `--version`, its argv after the tool's \
         name): no interpreter's \
         — and its options told by their hyphen (`starts_with('-')`)",
    ),
    (
        "crates/nn-core/src/decision/rules/program_identity.rs",
        4,
        "lot 313: the launchers' own options (`env -u NAME`, `VAR=value`, `timeout -s SIG`, \
         `stdbuf --output L`, `sudo -u user`…) a command line runs its program through \
         (`command_runs_a_shell`, socat's `EXEC:`), read to find that program: no \
         interpreter's; an interpreter found is read by the reader (`runs_of`) — and the \
         review of #549 (F4): the arguments of the program the dynamic loader runs \
         (`&argv[at..]`, `at` from the reader's `loader_program`)",
    ),
    (
        "crates/nn-core/src/decision/rules/r006_reverse_shell_tooling.rs",
        2,
        "lot 313: socat's addresses, every argument after its name (`.skip(1)`), each split on \
         `!!` and `|`: socat's own syntax, no interpreter's options; the review of #549 (F2): \
         the lineage's hops above a shell's parent (`hops.iter().skip(2)`), no argv",
    ),
    (
        "crates/nn-core/src/decision/rules/r015_encoding_tooling_service_uid.rs",
        2,
        "base64's and openssl's decoding options (`-d`, `--decode`): no interpreter's",
    ),
    (
        "crates/nn-core/src/decision/rules/r016_debugger_service_uid.rs",
        3,
        "gdb's and strace's attach options (`-p`, `--pid`, `--attach`): no interpreter's",
    ),
    (
        "crates/nn-core/src/decision/rules/r004_exec_from_proc_self_fd.rs",
        2,
        "the agent's own worker command line (`northnarrow-agent --worker <kind> --ipc-fd 3`, \
         R14a): an exact argv of the agent's, no interpreter's",
    ),
    (
        "crates/nn-core/src/posture/lineage.rs",
        10,
        "FP-2: npm's entrypoint as node's first argument exactly (`argv.get(1)`, twice): stricter \
         than the reader, which would take it after an option; a cgroup name's `-pod` and \
         `-conmon-` (no option) \
         — and `/proc` text fields read by position (`stat`, `mountinfo`, `cgroup`: \
         `.nth(n)`), no command line",
    ),
    (
        "crates/nn-admin/src/heartbeat.rs",
        1,
        "builds `sh -c <command>` for `--from-cmd` (a command line made, none read)",
    ),
    (
        "crates/nn-linux/src/worker/hostile.rs",
        1,
        "builds `sh -c` for the hostile worker of the sandbox's tests (a command line made)",
    ),
    (
        "crates/nn-linux/src/worker/serve.rs",
        6,
        "the agent's own worker command line (`--worker`, `--ipc-fd`, `--hostile`): read by the \
         worker itself, no interpreter's",
    ),
    (
        "crates/nn-linux/src/worker/spawn.rs",
        2,
        "builds the agent's worker command line (made, none read)",
    ),
    (
        "crates/nn-linux/src/telemetry_probe.rs",
        4,
        "the probe's own child's argv (its flag, then its nonce): the agent's command line",
    ),
    (
        "crates/nn-linux/src/telemetry_probe/deny.rs",
        1,
        "the deny self-test's child flag: the agent's command line",
    ),
    (
        "crates/nn-linux/src/self_integrity.rs",
        13,
        "the agent's own command-line flags its unit file must carry (`--net-scan-hosts`, …): \
         compared with the unit's text, no interpreter's",
    ),
    (
        "crates/nn-linux/src/host_hardening.rs",
        5,
        "install.sh's own flag read from the agent's install record (`--without-nftables`), \
         kernel release suffixes (`-rc`, `-generic`, `-default`): no interpreter's",
    ),
    (
        "crates/nn-linux/src/decision_host_linux.rs",
        2,
        "rpm's query options (`-qf`, `--quiet`): a command built",
    ),
    (
        "crates/nn-linux/src/response/block_outbound.rs",
        1,
        "nft's `-f`: a command built",
    ),
    (
        "agent/src/removed_settings.rs",
        5,
        "the agent's removed command-line flags, refused with a message: the agent's own",
    ),
    (
        "agent/src/boot/mod.rs",
        2,
        "the agent's own command line (its first argument, logged; `--worker`): no interpreter's",
    ),
    (
        "agent/src/boot/integrity.rs",
        1,
        "the agent's own `--detect-only` flag: no interpreter's",
    ),
    (
        "agent/src/boot/deny_selftest.rs",
        2,
        "the deny self-test's own child flags: the agent's command line",
    ),
    (
        "agent/src/cow/fanotify.rs",
        1,
        "a syscall's arguments (`args.get(idx)`: the open flags' register), no command line",
    ),
    (
        "agent/src/module_trust/scan.rs",
        2,
        "rpm's query options: a command built",
    ),
    (
        "agent/src/execq/pkgtrust.rs",
        2,
        "rpm's query options: a command built",
    ),
    (
        "watchdog/src/lib.rs",
        7,
        "the agent's command line the watchdog checks and builds (its flags, its argv): the \
         agent's own, no interpreter's \
         — and the agent's own `/proc/<pid>/cmdline` split on its NULs, a `/proc` stat \
         field (`.nth(19)`)",
    ),
    (
        "scan/src/main.rs",
        3,
        "the scanner's own command line (`--fd`, `--version`)",
    ),
    (
        "scan/src/supervisor.rs",
        1,
        "the scanner's child flag (`--fd`): a command built",
    ),
    (
        "common/src/cgroup_join.rs",
        1,
        "a name's suffix (`-cgroup-join-v`): no option",
    ),
    (
        "crates/nn-linux/src/module_writes.rs",
        1,
        "a name's suffix (`-module-writes`): no option",
    ),
    (
        "crates/nn-linux/src/sysctl_cgroup.rs",
        1,
        "a name's suffix (`-sysctl`): no option",
    ),
    (
        "agent/src/posture/golden.rs",
        2,
        "the golden files' lines compared by position (`.lines().nth`): no command line",
    ),
    (
        "antitamper-bpf/src/host_dropins.rs",
        2,
        "a drop-in's and a unit's text fields by position (`split_whitespace().nth(1)`, \
         `split(':').nth(1)`): systemd's syntax, no interpreter's options",
    ),
    (
        "crates/nn-linux/src/sensor_feasibility.rs",
        1,
        "a kernel text file's field by position (`split_whitespace().nth(2)`): no command line",
    ),
    (
        "crates/nn-linux/src/sensors/exec_facts.rs",
        1,
        "the exec's environment split on its NULs (`/proc/<pid>/environ`): variables, read \
         by name; `NODE_OPTIONS` goes to the reader (`node_options_load`)",
    ),
    (
        "crates/nn-linux/src/sensors/kmod_exec.rs",
        1,
        "a module tool's environment split on its NULs (`MODPROBE_OPTIONS`): kmod's, no \
         interpreter's",
    ),
    (
        "crates/nn-linux/src/sensors/ring_drops.rs",
        1,
        "`/proc/<pid>/status`'s `Uid:` fields by position: no command line (the cmdline \
         goes to the reader, `argv_of_cmdline`)",
    ),
    (
        "crates/nn-model/src/event.rs",
        1,
        "the exec record's argv blob split on its NULs: the decode of the kernel's record \
         into the argv the reader then reads",
    ),
    (
        "crates/nn-parse/src/dns_qname.rs",
        1,
        "a DNS name's bytes up to its NUL: no command line",
    ),
    (
        "scan/src/elf.rs",
        1,
        "an ELF string table split on its NULs: no command line",
    ),
    (
        "crates/nn-core/src/decision/rule_policy.rs",
        1,
        "a cgroup path's components after its root (`split('/').skip(1)`); the file names \
         `argv` only as a key the policy refuses: no command line",
    ),
];

fn which(text: &str) -> String {
    format!("{:?}", sites(text))
}

fn violations(code: &BTreeMap<String, String>) -> Vec<String> {
    let known: BTreeMap<&str, usize> = KNOWN.iter().map(|(f, n, _)| (*f, *n)).collect();
    let mut out = Vec::new();
    for (file, text) in code {
        if file == READER {
            continue;
        }
        let n = count(text);
        match known.get(file.as_str()) {
            None if n > 0 => out.push(format!(
                "{file}: {n} site(s), {} — an interpreter's options read by hand: read them \
                 with `posture::script_args` (`runs_of`, `ExecIdentity::of_exec`, \
                 `inline_program`), or list the file in KNOWN with why it is no interpreter's",
                which(text)
            )),
            Some(&pin) if n > pin => out.push(format!(
                "{file}: {n} sites, {pin} known — {}: a new one",
                which(text)
            )),
            Some(&pin) if n < pin => out.push(format!(
                "{file}: {n} sites, {pin} known — lower the pin (the ratchet only goes down)"
            )),
            _ => {}
        }
    }
    for (file, _, _) in KNOWN {
        if !code.contains_key(*file) {
            out.push(format!("{file}: listed in KNOWN, not in the scan"));
        }
    }
    out
}

/// No interpreter's option is read outside the reader; the pins are the
/// code's.
#[test]
fn interpreter_options_are_read_by_the_one_reader() {
    let code = product_code(&repo_root());
    assert!(code.contains_key(READER), "the reader is scanned");
    for crate_dir in [
        "crates/nn-export/src",
        "crates/nn-model/src",
        "cli/src",
        "scan/src",
    ] {
        assert!(
            code.keys().any(|f| f.starts_with(crate_dir)),
            "{crate_dir}: every product crate is scanned"
        );
    }
    let v = violations(&code);
    assert!(v.is_empty(), "{v:#?}");
    for (file, _, why) in KNOWN {
        assert!(why.len() > 20, "{file}: say why");
    }
}

/// Prints each file's count (`NN_PRINT_COUNTS=1`, by hand when the table
/// moves); a no-op without it.
#[test]
#[ignore = "prints the counts; NN_PRINT_COUNTS=1, run by hand when the table moves"]
fn print_the_counts() {
    if std::env::var_os("NN_PRINT_COUNTS").is_none() {
        return;
    }
    for (file, text) in product_code(&repo_root()) {
        let n = count(&text);
        if n > 0 && file != READER {
            println!("{n}\t{file}\t{}", which(&text));
        }
    }
}

/// The ratchet fails on planted violations: the seven twins of the review
/// of #539 — `.nth(1)` on a split cmdline (ring_drops' on main), `"--eval="`,
/// `== "-ec"`, `"--require"`, `cmd.get(idx + 1)` (R017's on main),
/// BUG-97's `-norc`, a search for `-c` — each in a new file; a known file
/// with one more site and one with one fewer; the reader itself is not
/// counted.
#[test]
fn the_ratchet_fails_on_planted_violations() {
    let root = repo_root();
    let mut code = product_code(&root);
    let planted: &[(&str, &str)] = &[
        (
            "nth",
            "fn a(c: &[u8]) -> bool { c.split(|b| *b == 0).nth(1).is_some() }\nfn b(cmdline: &[u8]) \
             -> bool { cmdline.split(|b| *b == 0).nth(1).is_some() }",
        ),
        ("eval", "fn a(s: &str) -> bool { s.starts_with(\"--eval=\") }"),
        ("ec", "fn a(s: &str) -> bool { s == \"-ec\" }"),
        ("require", "fn a(s: &str) -> bool { s == \"--require\" }"),
        ("idx", "fn a(cmd: &[String], idx: usize) -> Option<&String> { cmd.get(idx + 1) }"),
        ("norc", "fn a(argv: &[String]) -> bool { argv.iter().any(|x| x == \"-norc\") }"),
        ("pos", "fn a(argv: &[String]) -> Option<usize> { argv.iter().position(|a| a == \"-c\") }"),
    ];
    for (name, body) in planted {
        code.insert(
            format!(
                "crates/nn-core/src/posture/{}.rs",
                format_args!("twin_{name}")
            ),
            body.to_string(),
        );
    }
    code.get_mut("crates/nn-core/src/impair/mod.rs")
        .unwrap()
        .push_str("\nfn g(w: &str) -> bool { w == \"-c\" }\n");
    let lineage = code
        .get_mut("crates/nn-core/src/posture/lineage.rs")
        .unwrap();
    let i = lineage.find("argv.get(1)").expect("npm's entrypoint");
    lineage.replace_range(i..i + 4, "    ");
    code.get_mut(READER).unwrap().push_str(
        "\nfn h(argv: &[String]) -> bool { argv.get(1).is_some() && argv[1] == \"-c\" }\n",
    );
    let v = violations(&code);
    let new: Vec<&String> = v.iter().filter(|x| x.contains("/twin_")).collect();
    assert_eq!(new.len(), planted.len(), "{v:#?}");
    assert!(v
        .iter()
        .any(|x| x.contains("impair/mod.rs") && x.contains("a new one")));
    assert!(v
        .iter()
        .any(|x| x.contains("lineage.rs") && x.contains("lower the pin")));
    assert_eq!(v.len(), planted.len() + 2, "{v:#?}");
    // a file named `tests.rs` is test-only by its parent's `#[cfg(test)]`
    assert!(support::test_only_file(
        &root,
        "crates/nn-core/src/posture/tests.rs"
    ));
    assert!(!support::test_only_file(
        &root,
        "crates/nn-core/src/posture/lineage.rs"
    ));
}

/// The re-check of #539 (finding 9): the evasive twins — main's `ring_drops`
/// before lot 310, copied as it was (a cmdline split on its NULs, its second
/// word read across lines); the argv renamed (`let words = argv;
/// words.iter().nth(1)`); a cmdline's words skipped; an option told by its
/// hyphen by hand; an option's name built (`concat!("--", "eval")`); an
/// environment split on its NULs for a loader; a positional read on an
/// argv line — each in a new file, each caught. What a lexical ratchet
/// cannot catch is said in the PR: a positional read of a vector neither
/// named nor read as a command line in its file, an option's name built
/// without a hyphen literal (`format!`).
#[test]
fn the_re_check_s_evasive_twins_are_caught() {
    let mut code = product_code(&repo_root());
    let twins: &[(&str, &str)] = &[
        (
            "ring_drops_main",
            "fn a(base: &std::path::Path) -> bool {\n    std::fs::read(base.join(\"cmdline\"))\n        \
             .ok()\n        .and_then(|c| {\n            c.split(|b| *b == 0)\n                \
             .nth(1)\n                .map(|a| SCRIPTS.iter().any(|p| a == p.as_bytes()))\n        \
             })\n        .unwrap_or(false)\n}",
        ),
        (
            "renamed",
            "fn a(argv: &[String]) -> Option<&String> {\n    let words = argv;\n    \
             words.iter().nth(1)\n}",
        ),
        (
            "skipped",
            "fn a(cmdline: &[u8]) -> bool {\n    let mut w = cmdline\n        .split(|x| *x == 0);\n    \
             w.next();\n    w.next().is_some()\n}",
        ),
        (
            "hyphen",
            "fn a(argv: &[String]) -> bool {\n    argv.iter()\n        .any(|w| \
             w.strip_prefix('-').is_some_and(|f| f.contains('c')))\n}",
        ),
        (
            "built",
            "const EVAL: &str = concat!(\"--\", \"eval\");\nfn a(argv: &[String]) -> bool {\n    \
             argv.iter().any(|w| w == EVAL)\n}",
        ),
        (
            "environ",
            "fn a(env: &[u8]) -> bool {\n    env.split(|b| *b == 0)\n        .any(|v| \
             v.starts_with(b\"PYTHONPATH=\"))\n}",
        ),
        (
            "positional",
            "fn a(argv: &[String]) -> bool {\n    matches!(argv.get(1).map(String::as_str), \
             Some(x) if x.len() == 2)\n}",
        ),
    ];
    for (name, body) in twins {
        assert!(count(body) > 0, "{name}: no site counted in\n{body}");
        code.insert(
            format!(
                "crates/nn-core/src/posture/{}.rs",
                format_args!("evasive_{name}")
            ),
            body.to_string(),
        );
    }
    let v = violations(&code);
    for (name, _) in twins {
        assert!(
            v.iter().any(|x| x.contains(&format!("evasive_{name}.rs"))),
            "{name}: {v:#?}"
        );
    }
    assert_eq!(v.len(), twins.len(), "{v:#?}");
}
