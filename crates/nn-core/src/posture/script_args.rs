//! Lot 292 (external bug hunt, editions 1.2/1.3: BUG-44, BUG-42): what an
//! interpreter runs, read from its argv with the option table of that
//! interpreter.
//!
//! The identity of an interpreter's process is the script it runs
//! ([`crate::posture::lineage::ExecIdentity`]), and the argv that names it
//! is the caller's. An option read with the wrong arity moves the identity
//! onto a path the caller chose: `python3 -O /tmp/steal.py /usr/bin/aws`
//! ran `/tmp/steal.py` and was taken for the `aws` client when `-O` was
//! read as taking an argument (Python's takes none), `node -r /usr/lib/x.js
//! /tmp/e.js` for `/usr/lib/x.js` when `-r` was read as taking none, and
//! `sh -e script` for an inline program when a shell's `-e` (errexit) was
//! read as Perl's.
//!
//! So each interpreter family has its own table, from its documentation
//! and its option parser (`python3 --help`, perlrun and `perl.c`, `ruby.c`,
//! node's `node_options.cc`, bash's `shell.c`, dash), and the answer has
//! three values ([`Runs`]):
//!
//! - [`Runs::Script`]: every option before it was read with its arity, and
//!   the first argument that is not one names the script (or `-m` the
//!   module);
//! - [`Runs::Inline`]: the program is not named — an inline one (`-c`,
//!   `-e`), standard input (a shell's `-s`) or none (an interactive shell);
//! - [`Runs::Unknown`]: an option the table does not hold, or one whose
//!   argument is missing. What the interpreter runs is then not known: it
//!   is no client, no installed or packaged program, and it vouches for
//!   nothing below it. Only an option that is not in the table costs an
//!   identity, and only its trust: the table never guesses an arity, since
//!   either wrong guess hands the identity to a path the caller chose.

use std::path::Path;

/// What an interpreter runs, as its argv names it (lot 292).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Runs {
    /// A script path, or the module `-m` names (Python).
    Script(Box<str>),
    /// Nothing named: a binary, which runs its executable, or an
    /// interpreter running an inline program (`-c`, `-e`), standard input
    /// (a shell's `-s`) or nothing (an interactive shell).
    Inline,
    /// An interpreter whose options the table could not read: what it runs
    /// is not known. The first later argument that does not look like an
    /// option is kept, for a record and for a detection that looks for a
    /// staged script — never for trust.
    Unknown(Option<Box<str>>),
}

impl Runs {
    /// The script or module the process is known to run: never one of an
    /// argv the table could not read. What trust is decided on.
    pub fn script(&self) -> Option<&str> {
        match self {
            Runs::Script(s) => Some(s),
            Runs::Inline | Runs::Unknown(_) => None,
        }
    }

    /// The script it runs, or for an argv the table could not read the
    /// argument that may be it: for a record, and for a detection that
    /// looks for a staged script. Never for trust.
    pub fn mentioned(&self) -> Option<&str> {
        match self {
            Runs::Script(s) | Runs::Unknown(Some(s)) => Some(s),
            Runs::Inline | Runs::Unknown(None) => None,
        }
    }

    /// The program, for a record: the script an interpreter runs, else the
    /// executable; for an argv the table could not read, the executable
    /// and what may be its script, said as such.
    pub fn describe(&self, exe: &Path) -> String {
        match self {
            Runs::Script(s) => s.to_string(),
            Runs::Inline => exe.to_string_lossy().into_owned(),
            Runs::Unknown(Some(s)) => {
                format!("{} {s} (options not understood)", exe.display())
            }
            Runs::Unknown(None) => format!("{} (options not understood)", exe.display()),
        }
    }
}

/// The interpreter families, by executable basename: each has its table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Family {
    Python,
    Perl,
    Ruby,
    Node,
    /// bash, dash and `sh`: one table, their union (an option one of them
    /// refuses stops it before it runs anything).
    Shell,
    /// zsh and ksh: the options common to every shell only.
    OtherShell,
    Mono,
}

/// The family of an interpreter `exe`, by basename and a version suffix of
/// digits and dots (`python3.12`, `perl5.36`); `None` for any other
/// executable.
pub(crate) fn family_of(exe: &Path) -> Option<Family> {
    let base = exe.file_name()?.to_string_lossy();
    const NAMES: &[(&str, Family)] = &[
        ("python", Family::Python),
        ("perl", Family::Perl),
        ("ruby", Family::Ruby),
        ("nodejs", Family::Node),
        ("node", Family::Node),
        ("bash", Family::Shell),
        ("dash", Family::Shell),
        ("sh", Family::Shell),
        ("zsh", Family::OtherShell),
        ("ksh", Family::OtherShell),
        ("mono", Family::Mono),
    ];
    NAMES.iter().find_map(|(name, family)| {
        base.strip_prefix(name)
            .filter(|rest| rest.chars().all(|c| c.is_ascii_digit() || c == '.'))
            .map(|_| *family)
    })
}

/// How one option letter is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Opt {
    /// No argument: the letters after it are options too (`-O`, a shell's
    /// `-e`, `perl -w`).
    Flag,
    /// The rest of its argument, possibly empty (`perl -i.bak`, `-x`,
    /// `-F:`).
    Rest,
    /// The rest of its argument, which must not be empty (`perl -MFoo`:
    /// the interpreter refuses `-M` alone).
    RestRequired,
    /// The octal digits after it, then more letters (`perl -l`, `-0777`,
    /// `ruby -T`); for `x` after it, the hexadecimal digits (`perl -0x1F`).
    Digits,
    /// The rest of its argument, else the next argument (`python -W
    /// ignore`, `-Wignore`, `perl -I dir`, `ruby -r lib`).
    Arg,
    /// The next argument; the letters after it are options too (a shell's
    /// `-o pipefail`, bash's `-O extglob`: `-euo pipefail`).
    Next,
    /// The program is not named: inline (`-c`, `-e`) or standard input (a
    /// shell's `-s`).
    Inline,
    /// The module named by the rest of its argument, else the next (Python's
    /// `-m`).
    Module,
    /// Ruby's `-K`: one character (the code), then more letters.
    OneChar,
    /// Ruby's `-W`: `:category` (the rest), else one octal digit, then more
    /// letters.
    RubyWarn,
    /// Perl's `-d`: `t`, then `:module` or `=…` (the rest), else more
    /// letters (`perl -de 0`).
    PerlDebug,
}

/// The table of one family's single-letter options; `None`: not one.
fn short(family: Family, c: char) -> Option<Opt> {
    use Opt::*;
    let opt = match family {
        // `python3 --help` (3.8–3.14), and 2.7's -3, -t, -R, -U, -Q.
        Family::Python => match c {
            'b' | 'B' | 'd' | 'E' | 'h' | '?' | 'i' | 'I' | 'O' | 'P' | 'q' | 's' | 'S' | 'u'
            | 'v' | 'V' | 'x' | 'R' | 't' | 'U' | '3' => Flag,
            'W' | 'X' | 'Q' => Arg,
            'c' => Inline,
            'm' => Module,
            _ => return None,
        },
        // perlrun, as `perl.c` reads it (`moreswitches`, `parse_body`).
        Family::Perl => match c {
            'a' | 'c' | 'f' | 'g' | 'n' | 'p' | 's' | 'S' | 't' | 'T' | 'u' | 'U' | 'v' | 'w'
            | 'W' | 'X' | 'h' | '?' => Flag,
            'l' | '0' => Digits,
            'i' | 'x' | 'D' | 'C' | 'V' | 'F' => Rest,
            'm' | 'M' => RestRequired,
            'd' => PerlDebug,
            'I' => Arg,
            'e' | 'E' => Inline,
            _ => return None,
        },
        // `ruby.c` (`proc_options`).
        Family::Ruby => match c {
            'a' | 'p' | 'n' | 'd' | 'y' | 'v' | 'w' | 'c' | 's' | 'l' | 'S' | 'U' | 'h' => Flag,
            'r' | 'I' | 'C' | 'X' | 'E' => Arg,
            'i' | 'x' | 'F' => Rest,
            '0' | 'T' => Digits,
            'K' => OneChar,
            'W' => RubyWarn,
            'e' => Inline,
            _ => return None,
        },
        // node's own short options (it reads no other cluster than `-pe`,
        // handled before the table).
        Family::Node => match c {
            'i' | 'c' | 'v' | 'h' => Flag,
            'r' | 'C' => Arg,
            'e' | 'p' => Inline,
            _ => return None,
        },
        // bash's `shell.c` and dash: the set flags, bash's `-l`, `-r`,
        // `-D`, dash's `-I`, `-V`, `-E`; `-o` (and bash's `-O`) take the
        // next argument.
        Family::Shell => match c {
            'a' | 'b' | 'e' | 'f' | 'h' | 'i' | 'k' | 'l' | 'm' | 'n' | 'p' | 'r' | 't' | 'u'
            | 'v' | 'x' | 'B' | 'C' | 'D' | 'E' | 'H' | 'I' | 'P' | 'T' | 'V' => Flag,
            'o' | 'O' => Next,
            'c' | 's' => Inline,
            _ => return None,
        },
        // zsh and ksh: what every shell reads the same way.
        Family::OtherShell => match c {
            'a' | 'e' | 'f' | 'h' | 'i' | 'l' | 'm' | 'n' | 'u' | 'v' | 'x' | 'C' => Flag,
            'o' => Next,
            'c' | 's' => Inline,
            _ => return None,
        },
        Family::Mono => match c {
            'v' | 'V' | 'h' => Flag,
            _ => return None,
        },
    };
    Some(opt)
}

/// How a long option (`--name`, without `=`) is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Long {
    Flag,
    /// It takes the next argument.
    Arg,
    Inline,
}

/// The table of one family's long options; `None`: not one.
fn long(family: Family, name: &str) -> Option<Long> {
    use Long::*;
    let opt = match family {
        Family::Python => match name {
            "help" | "help-all" | "help-env" | "help-xoptions" | "version" => Flag,
            "check-hash-based-pycs" => Arg,
            _ => return None,
        },
        // perl reads `--help` and `--version` and refuses any other.
        Family::Perl => match name {
            "help" | "version" => Flag,
            _ => return None,
        },
        Family::Ruby => match name {
            "copyright" | "version" | "verbose" | "help" | "yydebug" | "debug" | "jit" | "yjit"
            | "rjit" | "mjit" => Flag,
            "enable" | "disable" | "encoding" | "external-encoding" | "internal-encoding"
            | "dump" | "backtrace-limit" | "crash-report" | "parser" => Arg,
            _ => return None,
        },
        Family::Node => return node_long(name),
        Family::Shell => match name {
            "login" | "noprofile" | "norc" | "posix" | "restricted" | "verbose" | "version"
            | "help" | "debugger" | "dump-po-strings" | "dump-strings" | "noediting"
            | "pretty-print" => Flag,
            "rcfile" | "init-file" => Arg,
            _ => return None,
        },
        Family::OtherShell => return None,
        Family::Mono => match name {
            "debug" | "verbose" | "server" | "desktop" | "llvm" | "nollvm" | "version" | "help" => {
                Flag
            }
            "config" => Arg,
            _ => return None,
        },
    };
    Some(opt)
}

/// node's long options (its `node_options.cc`, v18–v24; V8's flags read
/// with `_` or `-`). One that takes a value takes the next argument unless
/// it is written `--name=value`; `--no-…` negates a flag.
fn node_long(name: &str) -> Option<Long> {
    const ARG: &[&str] = &[
        "require",
        "import",
        "loader",
        "experimental-loader",
        "conditions",
        "input-type",
        "env-file",
        "env-file-if-exists",
        "title",
        "inspect-port",
        "debug-port",
        "inspect-publish-uid",
        "icu-data-dir",
        "openssl-config",
        "redirect-warnings",
        "report-dir",
        "report-directory",
        "report-filename",
        "report-signal",
        "secure-heap",
        "secure-heap-min",
        "tls-cipher-list",
        "tls-keylog",
        "unhandled-rejections",
        "use-largepages",
        "diagnostic-dir",
        "dns-result-order",
        "disable-warning",
        "disable-proto",
        "experimental-policy",
        "policy-integrity",
        "experimental-default-type",
        "experimental-specifier-resolution",
        "experimental-sea-config",
        "experimental-config-file",
        "heapsnapshot-signal",
        "heapsnapshot-near-heap-limit",
        "max-http-header-size",
        "cpu-prof-dir",
        "cpu-prof-name",
        "cpu-prof-interval",
        "heap-prof-dir",
        "heap-prof-name",
        "heap-prof-interval",
        "localstorage-file",
        "snapshot-blob",
        "watch-path",
        "allow-fs-read",
        "allow-fs-write",
        "trace-event-categories",
        "trace-event-file-pattern",
        "test-name-pattern",
        "test-skip-pattern",
        "test-reporter",
        "test-reporter-destination",
        "test-concurrency",
        "test-shard",
        "test-timeout",
        "run",
        "max-old-space-size",
        "max-semi-space-size",
        "stack-size",
        "stack-trace-limit",
    ];
    const FLAG: &[&str] = &[
        "help",
        "version",
        "v8-options",
        "completion-bash",
        "interactive",
        "check",
        "inspect",
        "inspect-brk",
        "inspect-wait",
        "enable-source-maps",
        "abort-on-uncaught-exception",
        "expose-gc",
        "trace-warnings",
        "trace-deprecation",
        "trace-uncaught",
        "trace-exit",
        "trace-sigint",
        "trace-sync-io",
        "trace-tls",
        "throw-deprecation",
        "pending-deprecation",
        "preserve-symlinks",
        "preserve-symlinks-main",
        "use-strict",
        "watch",
        "watch-preserve-output",
        "test",
        "test-only",
        "zero-fill-buffers",
        "prof",
        "prof-process",
        "cpu-prof",
        "heap-prof",
        "frozen-intrinsics",
        "insecure-http-parser",
        "jitless",
        "report-on-fatalerror",
        "report-uncaught-exception",
        "report-on-signal",
        "report-compact",
        "force-fips",
        "enable-fips",
        "openssl-legacy-provider",
        "openssl-shared-config",
        "use-bundled-ca",
        "use-openssl-ca",
        "use-system-ca",
        "permission",
        "experimental-permission",
        "allow-addons",
        "allow-child-process",
        "allow-wasi",
        "allow-worker",
        "experimental-vm-modules",
        "experimental-wasm-modules",
        "experimental-import-meta-resolve",
        "experimental-strip-types",
        "experimental-transform-types",
        "experimental-detect-module",
        "experimental-require-module",
        "experimental-modules",
        "experimental-json-modules",
        "experimental-repl-await",
        "experimental-top-level-await",
        "experimental-websocket",
        "experimental-fetch",
        "experimental-global-webcrypto",
        "experimental-sqlite",
        "experimental-webstorage",
        "experimental-network-imports",
        "experimental-test-coverage",
        "experimental-worker",
        "experimental-report",
        "harmony",
        "optimize-for-size",
        "single-threaded",
        "perf-basic-prof",
        "perf-prof",
        "interpreted-frames-native-stack",
        "allow-natives-syntax",
    ];
    let name = name.replace('_', "-");
    if name.starts_with("no-") || FLAG.contains(&name.as_str()) {
        return Some(Long::Flag);
    }
    if ARG.contains(&name.as_str()) {
        return Some(Long::Arg);
    }
    match name.as_str() {
        "eval" | "print" => Some(Long::Inline),
        _ => None,
    }
}

/// What `exe` runs for `argv` (its `argv[0]` first): [`Runs`]. A binary
/// runs its executable ([`Runs::Inline`]).
pub(crate) fn runs_of(exe: &Path, argv: &[String]) -> Runs {
    match family_of(exe) {
        Some(family) => read(family, argv),
        None => Runs::Inline,
    }
}

fn read(family: Family, argv: &[String]) -> Runs {
    let shell = matches!(family, Family::Shell | Family::OtherShell);
    let mut i = 1;
    while let Some(a) = argv.get(i) {
        i += 1;
        let unknown = move || Runs::Unknown(guess(argv, i, shell));
        let script = |at: usize| match argv.get(at) {
            Some(s) => Runs::Script(s.as_str().into()),
            None => Runs::Inline,
        };
        if a == "--" {
            return script(i);
        }
        if a == "-" {
            // bash and dash: the end of the options. The others: the
            // program comes from standard input, named `-` as it is.
            return match family {
                Family::Shell => script(i),
                Family::OtherShell => unknown(),
                _ => Runs::Script(a.as_str().into()),
            };
        }
        if let Some(name) = a.strip_prefix("--") {
            if name.contains('=') {
                // `--name=value` holds its value: it takes no argument
                continue;
            }
            match long(family, name) {
                Some(Long::Flag) => continue,
                Some(Long::Arg) => {
                    if argv.get(i).is_none() {
                        return unknown();
                    }
                    i += 1;
                    continue;
                }
                Some(Long::Inline) => return Runs::Inline,
                None => return unknown(),
            }
        }
        let letters = match a.strip_prefix('-') {
            Some(l) => l,
            None => match a.strip_prefix('+').filter(|_| shell) {
                // a shell's `+e`, `+o name`
                Some("") => return unknown(),
                Some(l) => l,
                None => return Runs::Script(a.as_str().into()),
            },
        };
        if family == Family::Node && letters == "pe" {
            return Runs::Inline;
        }
        // the arguments `Next` letters of this cluster take
        let mut next = 0;
        let mut pos = 0;
        while let Some(c) = letters[pos..].chars().next() {
            pos += c.len_utf8();
            let rest = &letters[pos..];
            let Some(opt) = short(family, c) else {
                return unknown();
            };
            match opt {
                Opt::Flag => {}
                Opt::Next => next += 1,
                Opt::Inline => return Runs::Inline,
                Opt::Rest => break,
                Opt::RestRequired if rest.is_empty() => return unknown(),
                Opt::RestRequired => break,
                Opt::Arg | Opt::Module => {
                    let value = if rest.is_empty() {
                        let Some(v) = argv.get(i) else {
                            return unknown();
                        };
                        i += 1;
                        v.as_str()
                    } else {
                        rest
                    };
                    if opt == Opt::Module {
                        return Runs::Script(value.into());
                    }
                    break;
                }
                Opt::Digits => {
                    pos += match rest.strip_prefix(['x', 'X']) {
                        Some(hex) if family == Family::Perl => {
                            1 + hex.bytes().take_while(u8::is_ascii_hexdigit).count()
                        }
                        _ => octal_digits(rest),
                    };
                }
                Opt::OneChar => pos += rest.chars().next().map_or(0, char::len_utf8),
                Opt::RubyWarn if rest.starts_with(':') => break,
                Opt::RubyWarn => pos += octal_digits(rest).min(1),
                Opt::PerlDebug => {
                    let after_t = rest.strip_prefix('t').unwrap_or(rest);
                    if after_t.starts_with([':', '=']) {
                        break;
                    }
                    pos += rest.len() - after_t.len();
                }
            }
        }
        if argv.len() < i + next {
            return unknown();
        }
        i += next;
    }
    Runs::Inline
}

/// What the script may be when the options could not be read: the first
/// argument from `from` on that does not look like an option.
fn guess(argv: &[String], from: usize, shell: bool) -> Option<Box<str>> {
    argv.get(from..)?
        .iter()
        .find(|a| !(a.starts_with('-') || (shell && a.starts_with('+'))))
        .map(|a| a.as_str().into())
}

/// The octal digits `s` starts with.
fn octal_digits(s: &str) -> usize {
    s.bytes().take_while(|b| (b'0'..=b'7').contains(b)).count()
}
