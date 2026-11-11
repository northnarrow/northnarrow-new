//! Lot 292 (external bug hunt, editions 1.2/1.3: BUG-44, BUG-42): what an
//! interpreter runs, read from its argv with the option table of that
//! interpreter. Lot 310 (edition 1.4: BUG-97, BUG-99, BUG-100, BUG-104,
//! N3): one reader for every family, in the style of `getopt`, over
//! declarative tables ([`Table`]) — and the only place in the tree that
//! reads an interpreter's options (`xtask/tests/interpreter_options.rs`).
//!
//! The identity of an interpreter's process is the script it runs
//! ([`crate::posture::lineage::ExecIdentity`]), and the argv that names it
//! is the caller's. An option read with the wrong arity moves the identity
//! onto a path the caller chose: `python3 -O /tmp/steal.py /usr/bin/aws`
//! ran `/tmp/steal.py` and was taken for the `aws` client when `-O` was
//! read as taking an argument (Python's takes none), `node -r /usr/lib/x.js
//! /tmp/e.js` for `/usr/lib/x.js` when `-r` was read as taking none, and
//! `sh -e script` for an inline program when a shell's `-e` (errexit) was
//! read as Perl's. Lot 310: `bash -noprofile /tmp/steal.sh x /usr/bin/aws`
//! was read as letters (`-noprofile`'s two `o` took two arguments) where
//! bash reads its long options with one hyphen too; `node
//! --eval=CODE /usr/bin/aws` skipped the table for `--name=value`; `node
//! --run task` read the task as an option's value; `zsh -ovi` gave zsh's
//! `-o` bash's arity; `/usr/bin/mono` resolved by the kernel to `mono-sgen`
//! was no interpreter at all, nor `busybox` running as `/bin/sh`.
//!
//! So each interpreter family has its own table, from its documentation
//! and its option parser (`python3 --help`, perlrun and `perl.c`, `ruby.c`,
//! node's `node_options.cc`, bash's `shell.c`, dash's `options.c`, zsh(1),
//! busybox's `ash.c`), the one reader ([`read`]) knows how each kind of
//! option is spelled — letters with their arity, clustered (`-euo
//! pipefail`); `--name` and `--name=value`; bash's long options with one
//! hyphen before its first cluster (`-norc`); an argument attached to its
//! letter (`-ovi`, `-Wignore`); a shell's `+` — and the answer has four
//! values ([`Runs`]):
//!
//! - [`Runs::Script`]: every option before it was read with its arity, and
//!   the first argument that is not one names the script (or `-m` the
//!   module);
//! - [`Runs::Code`]: the program is the caller's, named by no file: inline
//!   (`-c`, `-e`, `--eval`, `--print`), a `package.json` task (`node
//!   --run`) or standard input (a shell's `-s`);
//! - [`Runs::Inline`]: nothing named — a binary, or an interpreter running
//!   no program its argv gives (an interactive shell, a REPL);
//! - [`Runs::Unknown`]: an option the table does not hold, or one whose
//!   argument is missing. What the interpreter runs is then not known: it
//!   is no client, no installed or packaged program, and it vouches for
//!   nothing below it. Only an option that is not in the table costs an
//!   identity, and only its trust: the table never guesses an arity, since
//!   either wrong guess hands the identity to a path the caller chose.
//!
//! Residual, as a binary's `LD_PRELOAD` is (CM-25): an option that loads
//! the caller's code before the named script (`node -r`, `--import`, `perl
//! -M`, `-I`, `ruby -r`, `-I`) and the interpreter's environment
//! (`PYTHONPATH`, `NODE_OPTIONS`, `PERL5OPT`, `RUBYOPT`, `BASH_ENV`) are not
//! judged here: the identity is the script named. An interpreter no family
//! names (`php`, `lua`, `tclsh`, `deno`) is read as the binary it is.

use std::path::Path;

/// What an interpreter runs, as its argv names it (lot 292).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Runs {
    /// A script path, or the module `-m` names (Python).
    Script(Box<str>),
    /// Nothing named: a binary, which runs its executable, or an
    /// interpreter running no program its argv gives — an interactive
    /// shell, a REPL (or one reading a program from its standard input
    /// unasked, which its argv does not tell apart).
    Inline,
    /// Lot 310 (BUG-49, BUG-99): an interpreter running a program its argv
    /// carries — inline (`-c`, `-e`, `--eval`, `--print`), a task of the
    /// working directory's `package.json` (`node --run`) — or its standard
    /// input (a shell's `-s`): the caller's code, named by no file. It is
    /// no client and no installed program, and it vouches for nothing it
    /// starts.
    Code,
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
            Runs::Inline | Runs::Code | Runs::Unknown(_) => None,
        }
    }

    /// The script it runs, or for an argv the table could not read the
    /// argument that may be it: for a record, and for a detection that
    /// looks for a staged script. Never for trust.
    pub fn mentioned(&self) -> Option<&str> {
        match self {
            Runs::Script(s) | Runs::Unknown(Some(s)) => Some(s),
            Runs::Inline | Runs::Code | Runs::Unknown(None) => None,
        }
    }

    /// The program, for a record: the script an interpreter runs, else the
    /// executable; for an argv the table could not read, the executable
    /// and what may be its script, said as such.
    pub fn describe(&self, exe: &Path) -> String {
        match self {
            Runs::Script(s) => s.to_string(),
            Runs::Inline | Runs::Code => exe.to_string_lossy().into_owned(),
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
    /// zsh and the ksh family: the options common to every shell only.
    OtherShell,
    Mono,
    /// Lot 310: busybox, a binary of many programs: the one `argv[0]` names
    /// (`sh` when it is `/bin/sh`), or `argv[1]` after `busybox` itself. Its
    /// shells (`sh`, `ash`, `hush`, `bash`) are read as shells; any other
    /// program runs nothing named.
    Busybox,
}

/// The family of an interpreter `exe`, by basename and a version suffix of
/// digits and dots (`python3.12`, `perl5.36`), or (lot 310, BUG-104) one of
/// the names the kernel resolves an interpreter's usual name to
/// (`/usr/bin/mono` is a link to `mono-sgen`, Alpine's `/bin/sh` one to
/// `busybox`); `None` for any other executable.
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
        ("mksh", Family::OtherShell),
        ("lksh", Family::OtherShell),
        ("pdksh", Family::OtherShell),
        ("oksh", Family::OtherShell),
        ("mono", Family::Mono),
    ];
    /// What the kernel executes for an interpreter's usual name: Mono's
    /// runtimes (upstream's install and Debian's alternatives), busybox.
    const RESOLVED: &[(&str, Family)] = &[
        ("mono-sgen", Family::Mono),
        ("mono-boehm", Family::Mono),
        ("busybox", Family::Busybox),
    ];
    if let Some((_, family)) = RESOLVED.iter().find(|(name, _)| base == *name) {
        return Some(*family);
    }
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
    /// `ruby -T`).
    Digits,
    /// The rest of its argument, else the next argument (`python -W
    /// ignore`, `-Wignore`, `perl -I dir`, `ruby -r lib`, zsh's `-ovi`).
    Arg,
    /// The next argument; the letters after it are options too (a shell's
    /// `-o pipefail`, bash's `-O extglob`: `-euo pipefail`).
    Next,
    /// The program is the rest of its argument, else the next argument
    /// (`python -c`, `perl -e`, `node -e`): [`Runs::Code`].
    Code,
    /// A shell's `-c`: the program is its first argument that is not an
    /// option, after all of them (`bash -c -e 'cmd'`): [`Runs::Code`].
    ShellCode,
    /// A shell's `-s`: the program is its standard input: [`Runs::Code`].
    Stdin,
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

/// How a long option is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Long {
    /// No argument (with `=value`, the value is its own: `node
    /// --inspect=9229`).
    Flag,
    /// It takes the next argument, unless written `--name=value`.
    Arg,
    /// Its argument is the program ([`Runs::Code`]): `node --eval`,
    /// `--print`, `--run`, written either way.
    Code,
}

/// What a lone `-` means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Dash {
    /// The end of the options: the next argument is the script (bash, dash).
    EndOfOptions,
    /// The program is standard input, named `-` as it is.
    Stdin,
    /// Not known (zsh, ksh).
    Unknown,
}

/// One family's options, as its own parser reads them (lot 310: the one
/// reader, [`read`], reads every family through its table).
struct Table {
    /// Its single-letter options: the letters, and how each is read.
    short: &'static [(&'static str, Opt)],
    /// Its long options, `--name` or `--name=value`.
    long: &'static [(&'static str, Long)],
    /// Long options by the start of their name (`--no-…`, ruby's
    /// `--enable-…`).
    long_prefixes: &'static [(&'static str, Long)],
    /// bash (`parse_long_options` in `shell.c`): its long options are read
    /// with one hyphen or two (`-norc`, `--norc`), never with `=value`,
    /// and only before the first cluster of letters; after it, `--name`
    /// is refused ([`Runs::Unknown`]) and `-norc` is letters.
    words: bool,
    /// node: `_` in a long option's name reads as `-` (V8's flags).
    underscores: bool,
    /// A shell: `+` clusters (`+e`, `+o name`, busybox's `+c`).
    plus: bool,
    /// What a lone `-` means.
    dash: Dash,
}

impl Table {
    fn short(&self, c: char) -> Option<Opt> {
        self.short
            .iter()
            .find(|(letters, _)| letters.contains(c))
            .map(|(_, opt)| *opt)
    }

    fn long(&self, name: &str) -> Option<Long> {
        let name = if self.underscores {
            std::borrow::Cow::Owned(name.replace('_', "-"))
        } else {
            std::borrow::Cow::Borrowed(name)
        };
        let name = name.as_ref();
        self.long
            .iter()
            .find(|(n, _)| *n == name)
            .or_else(|| {
                self.long_prefixes
                    .iter()
                    .find(|(p, _)| name.len() > p.len() && name.starts_with(p))
            })
            .map(|(_, long)| *long)
    }
}

/// `python3 --help` (3.8–3.14), and 2.7's -3, -t, -R, -U, -Q.
const PYTHON: Table = Table {
    short: &[
        ("bBdEhiIOPqsSuvVxRtU3?", Opt::Flag),
        ("WXQ", Opt::Arg),
        ("c", Opt::Code),
        ("m", Opt::Module),
    ],
    long: &[
        ("help", Long::Flag),
        ("help-all", Long::Flag),
        ("help-env", Long::Flag),
        ("help-xoptions", Long::Flag),
        ("version", Long::Flag),
        ("check-hash-based-pycs", Long::Arg),
    ],
    long_prefixes: &[],
    words: false,
    underscores: false,
    plus: false,
    dash: Dash::Stdin,
};

/// perlrun, as `perl.c` reads it (`moreswitches`, `parse_body`); perl reads
/// `--help` and `--version` and refuses any other long option.
const PERL: Table = Table {
    short: &[
        ("acfgnpsStTuUvwWXh?", Opt::Flag),
        ("l0", Opt::Digits),
        ("ixDCVF", Opt::Rest),
        ("mM", Opt::RestRequired),
        ("d", Opt::PerlDebug),
        ("I", Opt::Arg),
        ("eE", Opt::Code),
    ],
    long: &[("help", Long::Flag), ("version", Long::Flag)],
    long_prefixes: &[],
    words: false,
    underscores: false,
    plus: false,
    dash: Dash::Stdin,
};

/// `ruby.c` (`proc_options`).
const RUBY: Table = Table {
    short: &[
        ("apndyvwcslSUh", Opt::Flag),
        ("rICXE", Opt::Arg),
        ("ixF", Opt::Rest),
        ("0T", Opt::Digits),
        ("K", Opt::OneChar),
        ("W", Opt::RubyWarn),
        ("e", Opt::Code),
    ],
    long: &[
        ("copyright", Long::Flag),
        ("version", Long::Flag),
        ("verbose", Long::Flag),
        ("help", Long::Flag),
        ("yydebug", Long::Flag),
        ("debug", Long::Flag),
        ("jit", Long::Flag),
        ("yjit", Long::Flag),
        ("rjit", Long::Flag),
        ("mjit", Long::Flag),
        ("enable", Long::Arg),
        ("disable", Long::Arg),
        ("encoding", Long::Arg),
        ("external-encoding", Long::Arg),
        ("internal-encoding", Long::Arg),
        ("dump", Long::Arg),
        ("backtrace-limit", Long::Arg),
        ("crash-report", Long::Arg),
        ("parser", Long::Arg),
    ],
    // `--disable-gems`: the feature joined by a hyphen; the JITs' tuning
    // (`--yjit-exec-mem-size=64`)
    long_prefixes: &[
        ("enable-", Long::Flag),
        ("disable-", Long::Flag),
        ("yjit-", Long::Flag),
        ("rjit-", Long::Flag),
        ("mjit-", Long::Flag),
    ],
    words: false,
    underscores: false,
    plus: false,
    dash: Dash::Stdin,
};

/// node's own options (its `node_options.cc`, v18–v24; V8's flags read
/// with `_` or `-`). One that takes a value takes the next argument unless
/// it is written `--name=value`; `--no-…` negates a flag. `-pe` is `-p`:
/// inline. Lot 310 (N3): `--run <task>` runs a task of the working
/// directory's `package.json` — the caller's, no file it names.
const NODE: Table = Table {
    short: &[("icvh", Opt::Flag), ("rC", Opt::Arg), ("ep", Opt::Code)],
    long: &[
        ("eval", Long::Code),
        ("print", Long::Code),
        ("run", Long::Code),
        ("require", Long::Arg),
        ("import", Long::Arg),
        ("loader", Long::Arg),
        ("experimental-loader", Long::Arg),
        ("conditions", Long::Arg),
        ("input-type", Long::Arg),
        ("env-file", Long::Arg),
        ("env-file-if-exists", Long::Arg),
        ("title", Long::Arg),
        ("inspect-port", Long::Arg),
        ("debug-port", Long::Arg),
        ("inspect-publish-uid", Long::Arg),
        ("icu-data-dir", Long::Arg),
        ("openssl-config", Long::Arg),
        ("redirect-warnings", Long::Arg),
        ("report-dir", Long::Arg),
        ("report-directory", Long::Arg),
        ("report-filename", Long::Arg),
        ("report-signal", Long::Arg),
        ("secure-heap", Long::Arg),
        ("secure-heap-min", Long::Arg),
        ("tls-cipher-list", Long::Arg),
        ("tls-keylog", Long::Arg),
        ("unhandled-rejections", Long::Arg),
        ("use-largepages", Long::Arg),
        ("diagnostic-dir", Long::Arg),
        ("dns-result-order", Long::Arg),
        ("disable-warning", Long::Arg),
        ("disable-proto", Long::Arg),
        ("experimental-policy", Long::Arg),
        ("policy-integrity", Long::Arg),
        ("experimental-default-type", Long::Arg),
        ("experimental-specifier-resolution", Long::Arg),
        ("experimental-sea-config", Long::Arg),
        ("experimental-config-file", Long::Arg),
        ("heapsnapshot-signal", Long::Arg),
        ("heapsnapshot-near-heap-limit", Long::Arg),
        ("max-http-header-size", Long::Arg),
        ("cpu-prof-dir", Long::Arg),
        ("cpu-prof-name", Long::Arg),
        ("cpu-prof-interval", Long::Arg),
        ("heap-prof-dir", Long::Arg),
        ("heap-prof-name", Long::Arg),
        ("heap-prof-interval", Long::Arg),
        ("localstorage-file", Long::Arg),
        ("snapshot-blob", Long::Arg),
        ("watch-path", Long::Arg),
        ("allow-fs-read", Long::Arg),
        ("allow-fs-write", Long::Arg),
        ("trace-event-categories", Long::Arg),
        ("trace-event-file-pattern", Long::Arg),
        ("test-name-pattern", Long::Arg),
        ("test-skip-pattern", Long::Arg),
        ("test-reporter", Long::Arg),
        ("test-reporter-destination", Long::Arg),
        ("test-concurrency", Long::Arg),
        ("test-shard", Long::Arg),
        ("test-timeout", Long::Arg),
        ("max-old-space-size", Long::Arg),
        ("max-semi-space-size", Long::Arg),
        ("stack-size", Long::Arg),
        ("stack-trace-limit", Long::Arg),
        ("help", Long::Flag),
        ("version", Long::Flag),
        ("v8-options", Long::Flag),
        ("completion-bash", Long::Flag),
        ("interactive", Long::Flag),
        ("check", Long::Flag),
        ("inspect", Long::Flag),
        ("inspect-brk", Long::Flag),
        ("inspect-wait", Long::Flag),
        ("enable-source-maps", Long::Flag),
        ("abort-on-uncaught-exception", Long::Flag),
        ("expose-gc", Long::Flag),
        ("trace-warnings", Long::Flag),
        ("trace-deprecation", Long::Flag),
        ("trace-uncaught", Long::Flag),
        ("trace-exit", Long::Flag),
        ("trace-sigint", Long::Flag),
        ("trace-sync-io", Long::Flag),
        ("trace-tls", Long::Flag),
        ("throw-deprecation", Long::Flag),
        ("pending-deprecation", Long::Flag),
        ("preserve-symlinks", Long::Flag),
        ("preserve-symlinks-main", Long::Flag),
        ("use-strict", Long::Flag),
        ("watch", Long::Flag),
        ("watch-preserve-output", Long::Flag),
        ("test", Long::Flag),
        ("test-only", Long::Flag),
        ("zero-fill-buffers", Long::Flag),
        ("prof", Long::Flag),
        ("prof-process", Long::Flag),
        ("cpu-prof", Long::Flag),
        ("heap-prof", Long::Flag),
        ("frozen-intrinsics", Long::Flag),
        ("insecure-http-parser", Long::Flag),
        ("jitless", Long::Flag),
        ("report-on-fatalerror", Long::Flag),
        ("report-uncaught-exception", Long::Flag),
        ("report-on-signal", Long::Flag),
        ("report-compact", Long::Flag),
        ("force-fips", Long::Flag),
        ("enable-fips", Long::Flag),
        ("openssl-legacy-provider", Long::Flag),
        ("openssl-shared-config", Long::Flag),
        ("use-bundled-ca", Long::Flag),
        ("use-openssl-ca", Long::Flag),
        ("use-system-ca", Long::Flag),
        ("permission", Long::Flag),
        ("experimental-permission", Long::Flag),
        ("allow-addons", Long::Flag),
        ("allow-child-process", Long::Flag),
        ("allow-wasi", Long::Flag),
        ("allow-worker", Long::Flag),
        ("experimental-vm-modules", Long::Flag),
        ("experimental-wasm-modules", Long::Flag),
        ("experimental-import-meta-resolve", Long::Flag),
        ("experimental-strip-types", Long::Flag),
        ("experimental-transform-types", Long::Flag),
        ("experimental-detect-module", Long::Flag),
        ("experimental-require-module", Long::Flag),
        ("experimental-modules", Long::Flag),
        ("experimental-json-modules", Long::Flag),
        ("experimental-repl-await", Long::Flag),
        ("experimental-top-level-await", Long::Flag),
        ("experimental-websocket", Long::Flag),
        ("experimental-fetch", Long::Flag),
        ("experimental-global-webcrypto", Long::Flag),
        ("experimental-sqlite", Long::Flag),
        ("experimental-webstorage", Long::Flag),
        ("experimental-network-imports", Long::Flag),
        ("experimental-test-coverage", Long::Flag),
        ("experimental-worker", Long::Flag),
        ("experimental-report", Long::Flag),
        ("harmony", Long::Flag),
        ("optimize-for-size", Long::Flag),
        ("single-threaded", Long::Flag),
        ("perf-basic-prof", Long::Flag),
        ("perf-prof", Long::Flag),
        ("interpreted-frames-native-stack", Long::Flag),
        ("allow-natives-syntax", Long::Flag),
    ],
    // `--no-…` negates a flag; V8's `--harmony-…` are flags
    long_prefixes: &[("no-", Long::Flag), ("harmony-", Long::Flag)],
    words: false,
    underscores: true,
    plus: false,
    dash: Dash::Stdin,
};

/// bash's `shell.c` and dash's `options.c`, and busybox's ash and hush: the
/// set flags, bash's `-l`, `-r`, `-D`, dash's `-I`, `-V`, `-E`; `-o` (and
/// bash's `-O`) take the next argument (`-ovi` is `-o` then `-v -i`); `-c`
/// and `-s` with either sign (busybox reads `+c` as `-c`). bash's long
/// options (`long_args` in `shell.c`, 5.2), with one hyphen or two, before
/// the first cluster ([`Table::words`]); dash and busybox refuse them.
const SHELL: Table = Table {
    short: &[
        ("abefhiklmnprtuvxBCDEHIPTV", Opt::Flag),
        ("oO", Opt::Next),
        ("c", Opt::ShellCode),
        ("s", Opt::Stdin),
    ],
    long: &[
        ("debug", Long::Flag),
        ("debugger", Long::Flag),
        ("dump-po-strings", Long::Flag),
        ("dump-strings", Long::Flag),
        ("help", Long::Flag),
        ("login", Long::Flag),
        ("noediting", Long::Flag),
        ("noprofile", Long::Flag),
        ("norc", Long::Flag),
        ("posix", Long::Flag),
        ("pretty-print", Long::Flag),
        ("restricted", Long::Flag),
        ("verbose", Long::Flag),
        ("version", Long::Flag),
        ("init-file", Long::Arg),
        ("rcfile", Long::Arg),
    ],
    long_prefixes: &[],
    words: true,
    underscores: false,
    plus: true,
    dash: Dash::EndOfOptions,
};

/// zsh and the ksh family: what every shell reads the same way, and `-o`
/// with its name attached or next (zsh(1): `-xoshwordsplit` is `-x -o
/// shwordsplit`; ksh's getopt). Lot 310 (BUG-100): it had bash's arity.
const OTHER_SHELL: Table = Table {
    short: &[
        ("aefhilmnuvxC", Opt::Flag),
        ("o", Opt::Arg),
        ("c", Opt::ShellCode),
        ("s", Opt::Stdin),
    ],
    long: &[],
    long_prefixes: &[],
    words: false,
    underscores: false,
    plus: true,
    dash: Dash::Unknown,
};

/// mono(1).
const MONO: Table = Table {
    short: &[("vVh", Opt::Flag)],
    long: &[
        ("debug", Long::Flag),
        ("verbose", Long::Flag),
        ("server", Long::Flag),
        ("desktop", Long::Flag),
        ("llvm", Long::Flag),
        ("nollvm", Long::Flag),
        ("version", Long::Flag),
        ("help", Long::Flag),
        ("config", Long::Arg),
    ],
    long_prefixes: &[],
    words: false,
    underscores: false,
    plus: false,
    dash: Dash::Stdin,
};

/// busybox's shells.
const BUSYBOX_SHELLS: &[&str] = &["sh", "ash", "hush", "bash"];

/// What `exe` runs for `argv` (its `argv[0]` first): [`Runs`]. A binary
/// runs its executable ([`Runs::Inline`]).
pub(crate) fn runs_of(exe: &Path, argv: &[String]) -> Runs {
    reading(exe, argv).runs
}

/// Lot 310: the program an interpreter's argv carries inline (`-c CMD`,
/// `-e CODE`, `--eval=CODE`), for a record; `None` when it runs none, or
/// its options could not be read.
pub(crate) fn inline_program<'a>(exe: &Path, argv: &'a [String]) -> Option<&'a str> {
    let (at, from) = reading(exe, argv).code?;
    argv.get(at)?.get(from..)
}

/// What one argv reads as.
struct Reading {
    runs: Runs,
    /// With [`Runs::Code`], where the program is: an argument, and the
    /// byte its text starts at (`-cCMD`, `--eval=CODE`).
    code: Option<(usize, usize)>,
}

impl From<Runs> for Reading {
    fn from(runs: Runs) -> Self {
        Self { runs, code: None }
    }
}

fn reading(exe: &Path, argv: &[String]) -> Reading {
    let table = match family_of(exe) {
        None => return Runs::Inline.into(),
        Some(Family::Python) => &PYTHON,
        Some(Family::Perl) => &PERL,
        Some(Family::Ruby) => &RUBY,
        Some(Family::Node) => &NODE,
        Some(Family::Shell) => &SHELL,
        Some(Family::OtherShell) => &OTHER_SHELL,
        Some(Family::Mono) => &MONO,
        Some(Family::Busybox) => {
            // busybox's `main`: the program `argv[0]` names (a login
            // shell's `-` dropped), or with `busybox` itself the next
            // argument's (one starting with `-` is busybox's own option)
            let base = |a: &str| a.rsplit('/').next().unwrap_or(a).to_string();
            let named = argv.first().map(|a| base(a.strip_prefix('-').unwrap_or(a)));
            let (program, from) = match named.as_deref() {
                Some("busybox") => match argv.get(1) {
                    Some(a) if !a.starts_with('-') => (base(a), 2),
                    _ => return Runs::Inline.into(),
                },
                Some(p) => (p.to_string(), 1),
                None => return Runs::Inline.into(),
            };
            if !BUSYBOX_SHELLS.contains(&program.as_str()) {
                return Runs::Inline.into();
            }
            return read(&SHELL, argv, from);
        }
    };
    read(table, argv, 1)
}

/// The one reader: `argv` from `from` on, through `table`.
fn read(table: &Table, argv: &[String], from: usize) -> Reading {
    let mut i = from;
    // bash: its long options with one hyphen, before the first cluster
    let mut words = table.words;
    // a shell's `-c`: its program is the first operand after the options
    let mut shell_code = false;
    while let Some(a) = argv.get(i) {
        i += 1;
        let unknown = move || Runs::Unknown(guess(argv, i, table.plus)).into();
        if a == "--" {
            return operand(argv, i, shell_code);
        }
        if a == "-" {
            return match table.dash {
                Dash::EndOfOptions => operand(argv, i, shell_code),
                Dash::Stdin => Runs::Script(a.as_str().into()).into(),
                Dash::Unknown => unknown(),
            };
        }
        if words {
            if let Some(name) = a.strip_prefix('-') {
                let two = name.strip_prefix('-');
                match table.long(two.unwrap_or(name)) {
                    // never `=value`: `--rcfile=f` is no option of bash's
                    Some(Long::Flag) => continue,
                    Some(Long::Arg) => {
                        if argv.get(i).is_none() {
                            return unknown();
                        }
                        i += 1;
                        continue;
                    }
                    Some(Long::Code) => return Runs::Code.into(),
                    // letters from here on; a `--name` bash does not know is
                    // refused below
                    None => words = false,
                }
            }
        }
        if let Some(name) = a.strip_prefix("--") {
            if table.words {
                // bash, after its first cluster: refused
                return unknown();
            }
            let (name, value) = match name.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (name, None),
            };
            match table.long(name) {
                Some(Long::Flag) => continue,
                Some(Long::Arg) => {
                    if value.is_none() {
                        if argv.get(i).is_none() {
                            return unknown();
                        }
                        i += 1;
                    }
                    continue;
                }
                Some(Long::Code) => {
                    let code = match value {
                        Some(_) => Some((i - 1, a.len() - value.map_or(0, str::len))),
                        None => argv.get(i).map(|_| (i, 0)),
                    };
                    return Reading {
                        runs: Runs::Code,
                        code,
                    };
                }
                None => return unknown(),
            }
        }
        let letters = match a.strip_prefix('-') {
            Some(l) => l,
            None => match a.strip_prefix('+').filter(|_| table.plus) {
                // a shell's `+e`, `+o name`
                Some("") => return unknown(),
                Some(l) => l,
                None => return operand(argv, i - 1, shell_code),
            },
        };
        words = false;
        // the arguments `Next` letters of this cluster take
        let mut next = 0;
        let mut pos = 0;
        while let Some(c) = letters[pos..].chars().next() {
            pos += c.len_utf8();
            let rest = &letters[pos..];
            let Some(opt) = table.short(c) else {
                return unknown();
            };
            match opt {
                Opt::Flag => {}
                Opt::Next => next += 1,
                Opt::Stdin => return Runs::Code.into(),
                // the rest of the cluster is options too, then its operands
                Opt::ShellCode => shell_code = true,
                Opt::Code => {
                    let start = a.len() - rest.len();
                    let code = if rest.is_empty() {
                        argv.get(i).map(|_| (i, 0))
                    } else {
                        Some((i - 1, start))
                    };
                    return Reading {
                        runs: Runs::Code,
                        code,
                    };
                }
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
                        return Runs::Script(value.into()).into();
                    }
                    break;
                }
                // Perl's `-0x1F`: the `x` then reads as `-x`, which takes
                // the rest, as the hexadecimal digits would
                Opt::Digits => pos += octal_digits(rest),
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
    if shell_code {
        // `bash -c` with no program: bash refuses
        return Runs::Code.into();
    }
    Runs::Inline.into()
}

/// The first argument that is not an option, at `at`: the script; after a
/// shell's `-c`, its program ([`Runs::Code`]); none, [`Runs::Inline`].
fn operand(argv: &[String], at: usize, shell_code: bool) -> Reading {
    match argv.get(at) {
        _ if shell_code => Reading {
            runs: Runs::Code,
            code: argv.get(at).map(|_| (at, 0)),
        },
        Some(s) => Runs::Script(s.as_str().into()).into(),
        None => Runs::Inline.into(),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every family reads any cluster of up to three characters — ASCII,
    /// a multi-byte one, the option letters of every table — without a
    /// panic, and a script it names is in that argument (no argument past
    /// the argv's end).
    #[test]
    fn any_cluster_is_read_without_a_panic() {
        let alphabet: Vec<char> = "abcdeEfFhiIklmMnoOprsStTuvVwWxX0179:=-+.é…"
            .chars()
            .collect();
        let exes = [
            "/usr/bin/python3",
            "/usr/bin/perl",
            "/usr/bin/ruby",
            "/usr/bin/node",
            "/usr/bin/bash",
            "/usr/bin/zsh",
            "/usr/bin/mono",
            "/bin/busybox",
        ];
        let mut clusters = vec![String::new()];
        for _ in 0..3 {
            let mut next = Vec::new();
            for c in &clusters {
                for a in &alphabet {
                    next.push(format!("{c}{a}"));
                }
            }
            clusters.extend(next);
        }
        for exe in exes {
            for c in &clusters {
                for prefix in ["-", "--", "+", ""] {
                    // busybox runs its shell for the name `sh`
                    let argv0 = if exe.ends_with("busybox") { "sh" } else { "x" };
                    let argv = vec![argv0.to_string(), format!("{prefix}{c}")];
                    match runs_of(Path::new(exe), &argv) {
                        // the argument itself, or the module `-m` names in it
                        Runs::Script(s) => assert!(argv[1].ends_with(&*s), "{exe} {argv:?}"),
                        Runs::Inline | Runs::Code | Runs::Unknown(_) => {}
                    }
                    // an inline program is in the argv
                    if let Some(p) = inline_program(Path::new(exe), &argv) {
                        assert!(argv[1].ends_with(p), "{exe} {argv:?} {p:?}");
                    }
                }
            }
        }
    }
    fn argv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    // ── Lot 310 (external bug hunt, edition 1.4) ────────────────────────

    /// BUG-97: bash reads its long options with one hyphen too (`-norc`,
    /// `-rcfile f`: `parse_long_options` in `shell.c`, before the first
    /// letter cluster). Checked with bash 5.2.21: `bash -noprofile ./s x
    /// /usr/bin/true` runs `./s`. Read as letters, `-noprofile`'s two `o`
    /// took two arguments and the identity moved to the caller's path.
    #[test]
    fn bug97_noprofile_with_one_hyphen_names_the_script() {
        use crate::posture::lineage::ExecIdentity;
        let a = argv(&["bash", "-noprofile", "/tmp/steal.sh", "x", "/usr/bin/aws"]);
        let id = ExecIdentity::of_exec("/usr/bin/bash", &a);
        assert_eq!(
            (
                id.runs.clone(),
                id.is_client(&["aws"]),
                id.is_installed_program()
            ),
            (Runs::Script("/tmp/steal.sh".into()), false, false),
            "BUG-97: `bash -noprofile /tmp/steal.sh x /usr/bin/aws` runs /tmp/steal.sh"
        );
    }

    #[test]
    fn bug97_other_one_hyphen_words_name_the_script() {
        let mut wrong = Vec::new();
        for a in [
            &["bash", "-norc", "/tmp/steal.sh"][..],
            &["bash", "-posix", "/tmp/steal.sh"],
            &["bash", "-restricted", "/tmp/steal.sh"],
            &["bash", "-verbose", "/tmp/steal.sh"],
            &["bash", "-rcfile", "/etc/x", "/tmp/steal.sh"],
            &["bash", "-init-file", "/etc/x", "/tmp/steal.sh"],
            &["bash", "-login", "-noediting", "/tmp/steal.sh"],
            &["bash", "-debug", "-pretty-print", "/tmp/steal.sh"],
            &["bash", "-norc", "--noprofile", "-e", "/tmp/steal.sh"],
        ] {
            let got = runs_of(Path::new("/usr/bin/bash"), &argv(a));
            if got != Runs::Script("/tmp/steal.sh".into()) {
                wrong.push(format!("{a:?} -> {got:?}"));
            }
        }
        assert!(wrong.is_empty(), "BUG-97: script not named: {wrong:#?}");
    }

    /// bash reads its long options only before its first cluster: after
    /// it, a word is letters (`bash -e -norc s` is refused by bash 5.2:
    /// `-o` takes `s` as an option name) and `--norc` is refused; `=value`
    /// is no form of bash's. None of them names a script.
    #[test]
    fn bug97_words_only_before_the_first_cluster() {
        let bash = Path::new("/usr/bin/bash");
        assert_eq!(
            runs_of(
                bash,
                &argv(&["bash", "--noprofile", "/tmp/s.sh", "x", "/usr/bin/aws"])
            ),
            Runs::Script("/tmp/s.sh".into())
        );
        for a in [
            &["bash", "-e", "-norc", "/tmp/s.sh"][..],
            &["bash", "-e", "--norc", "/tmp/s.sh"],
            &["bash", "--rcfile=/etc/x", "/tmp/s.sh"],
            &["bash", "--nosuch", "/tmp/s.sh"],
            &["bash", "-rcfile"],
        ] {
            let got = runs_of(bash, &argv(a));
            assert_eq!(got.script(), None, "{a:?} -> {got:?}");
        }
        // dash and busybox refuse the words: `-noprofile` is letters there,
        // and its `-o` takes the script as an option name — nothing runs,
        // whatever is read
    }

    /// BUG-99: `node --eval=CODE file` runs CODE; the `--name=value` branch
    /// skipped the table and the next argument became the script.
    #[test]
    fn bug99_node_eval_equals_code_is_inline_code() {
        use crate::posture::lineage::ExecIdentity;
        let mut wrong = Vec::new();
        for a in [
            &[
                "node",
                "--eval=require('/tmp/e.js')",
                "/usr/lib/node_modules/npm/bin/npm-cli.js",
            ][..],
            &["node", "--eval=steal()", "/usr/bin/aws"],
            &["node", "--print=steal()", "/usr/bin/aws"],
            &["node", "--no-warnings", "--print=steal()", "/usr/bin/aws"],
            &["nodejs", "-pe", "steal()", "/usr/bin/aws"],
        ] {
            let id = ExecIdentity::of_exec("/usr/bin/node", &argv(a));
            if (
                id.runs.clone(),
                id.is_installed_program(),
                id.is_client(&["aws"]),
            ) != (Runs::Code, false, false)
            {
                wrong.push(format!(
                    "{a:?} -> {:?}, installed {}, client aws {}",
                    id.runs,
                    id.is_installed_program(),
                    id.is_client(&["aws"])
                ));
            }
        }
        assert!(
            wrong.is_empty(),
            "BUG-99: inline code taken for a script: {wrong:#?}"
        );
    }

    /// N3 (new in the triage): `node --run <task> [args]` runs a task of the
    /// working directory's package.json (the caller's), not a file; `run`
    /// was read as an option with a value, so the next argument became the
    /// script (identity `/usr/bin/aws`).
    #[test]
    fn n3_node_run_names_no_script() {
        use crate::posture::lineage::ExecIdentity;
        for a in [
            &["node", "--run", "build", "/usr/bin/aws"][..],
            &["node", "--run=build", "/usr/bin/aws"],
        ] {
            let id = ExecIdentity::of_exec("/usr/bin/node", &argv(a));
            assert!(
                id.runs == Runs::Code && !id.is_client(&["aws"]) && !id.is_installed_program(),
                "node --run: no script is named, yet {:?}",
                id.runs
            );
        }
    }

    /// The separate form, and `--name=value` of an option that takes a
    /// value; an option the table does not hold is never a script, with a
    /// value or without.
    #[test]
    fn bug99_guard_separate_eval_and_valued_options() {
        let node = Path::new("/usr/bin/node");
        assert_eq!(
            runs_of(node, &argv(&["node", "--eval", "steal()", "/usr/bin/aws"])),
            Runs::Code
        );
        assert_eq!(
            runs_of(
                node,
                &argv(&["node", "--require=/usr/lib/x.js", "/tmp/e.js"])
            ),
            Runs::Script("/tmp/e.js".into())
        );
        assert_eq!(
            runs_of(
                node,
                &argv(&[
                    "node",
                    "--max_old_space_size=64",
                    "--inspect=9229",
                    "/tmp/e.js"
                ])
            ),
            Runs::Script("/tmp/e.js".into())
        );
        for a in [
            &["node", "--nosuch=1", "/tmp/e"][..],
            &["python3", "--nosuch=1", "/tmp/e"],
            &["ruby", "--nosuch=1", "/tmp/e"],
            &["mono", "--nosuch=1", "/tmp/e"],
        ] {
            let got = runs_of(Path::new(&format!("/usr/bin/{}", a[0])), &argv(a));
            assert_eq!(got, Runs::Unknown(Some("/tmp/e".into())), "{a:?}");
        }
    }

    /// BUG-100: zsh reads `-ovi` as `-o vi` (zsh(1) INVOCATION:
    /// "-xoshwordsplit is equivalent to -x -o shwordsplit"); the zsh and ksh
    /// table gave `o` bash's arity, so the script was taken as the option's
    /// name.
    #[test]
    fn bug100_zsh_o_with_its_name_attached_keeps_the_script() {
        use crate::posture::lineage::ExecIdentity;
        let id = ExecIdentity::of_exec(
            "/usr/bin/zsh",
            &argv(&["zsh", "-ovi", "/tmp/steal.zsh", "/usr/bin/aws"]),
        );
        assert_eq!(
            (
                id.script().map(str::to_string),
                id.is_client(&["aws"]),
                id.is_installed_program()
            ),
            (Some("/tmp/steal.zsh".to_string()), false, false),
            "BUG-100: `zsh -ovi /tmp/steal.zsh /usr/bin/aws` taken for {:?}",
            id.runs
        );
    }

    #[test]
    fn bug100_other_attached_o_forms_name_the_script() {
        let mut wrong = Vec::new();
        for (exe, a) in [
            (
                "/usr/bin/zsh",
                &["zsh", "-eovi", "/tmp/s", "/usr/bin/aws"][..],
            ),
            ("/usr/bin/zsh", &["zsh", "+ovi", "/tmp/s", "/usr/bin/aws"]),
            ("/usr/bin/zsh", &["zsh", "-onounset", "/tmp/s"]),
            ("/usr/bin/ksh93", &["ksh93", "-onoclobber", "/tmp/s"]),
            ("/usr/bin/mksh", &["mksh", "-onoclobber", "/tmp/s"]),
        ] {
            let got = runs_of(Path::new(exe), &argv(a));
            if got != Runs::Script("/tmp/s".into()) {
                wrong.push(format!("{a:?} -> {got:?}"));
            }
        }
        assert!(wrong.is_empty(), "BUG-100: {wrong:#?}");
    }

    /// `-o name` separate, and bash's `-o` (the next argument) unchanged:
    /// `bash -ovi` is `-o` then `-v -i`, as bash reads it.
    #[test]
    fn bug100_guard_separate_o_and_bash() {
        assert_eq!(
            runs_of(
                Path::new("/usr/bin/zsh"),
                &argv(&["zsh", "-o", "vi", "/tmp/s"])
            ),
            Runs::Script("/tmp/s".into())
        );
        assert_eq!(
            runs_of(
                Path::new("/usr/bin/bash"),
                &argv(&["bash", "-euo", "pipefail", "/tmp/s"])
            ),
            Runs::Script("/tmp/s".into())
        );
        assert_eq!(
            runs_of(
                Path::new("/usr/bin/bash"),
                &argv(&["bash", "-ovi", "/tmp/s"])
            ),
            Runs::Inline
        );
    }

    /// BUG-104: `/usr/bin/mono` is a link to `mono-sgen` (upstream's
    /// install, Debian's alternatives); the exec sensor's default (LSM)
    /// path is the file the kernel opened, so a `mono x.exe` process is
    /// judged by `mono-sgen`, which `family_of` did not know.
    #[test]
    fn bug104_mono_sgen_is_mono() {
        use crate::posture::lineage::{is_interpreter, ExecIdentity};
        for exe in ["/usr/bin/mono-sgen", "/usr/bin/mono-boehm"] {
            let id = ExecIdentity::of_exec(exe, &argv(&["mono", "/tmp/evil.exe"]));
            assert_eq!(
                (
                    is_interpreter(Path::new(exe)),
                    id.runs.clone(),
                    id.is_installed_program()
                ),
                (true, Runs::Script("/tmp/evil.exe".into()), false),
                "BUG-104: `mono /tmp/evil.exe` under the kernel-resolved {exe}"
            );
        }
    }

    /// The other face: KeePass 2 under mono-sgen is its store's client
    /// (NN-L-FIM-016, KillProcess, killed it).
    #[test]
    fn bug104_keepass_under_mono_sgen_is_its_client() {
        use crate::posture::lineage::ExecIdentity;
        let a = argv(&["mono", "/usr/lib/keepass2/KeePass.exe"]);
        assert!(ExecIdentity::of_exec("/usr/bin/mono", &a).is_client(&["KeePass.exe"]));
        let id = ExecIdentity::of_exec("/usr/bin/mono-sgen", &a);
        assert!(
            id.is_client(&["KeePass.exe"]),
            "BUG-104: KeePass 2 under /usr/bin/mono-sgen is not its store's client: {:?}",
            id.runs
        );
    }

    /// Lot 310 (BUG-104's sibling): busybox as `/bin/sh` (Alpine, its
    /// containers) runs the program `argv[0]` names, or the one after
    /// `busybox`: its shells are read as shells — a script from `/tmp` is no
    /// installed program, `-c` is inline code — and any other program runs
    /// nothing named.
    #[test]
    fn busybox_runs_the_program_argv_names() {
        use crate::posture::lineage::ExecIdentity;
        let bb = "/bin/busybox";
        for (a, want) in [
            (
                &["sh", "/tmp/steal.sh", "/usr/bin/aws"][..],
                Runs::Script("/tmp/steal.sh".into()),
            ),
            (
                &["/bin/ash", "-e", "/tmp/steal.sh"],
                Runs::Script("/tmp/steal.sh".into()),
            ),
            (
                &["busybox", "sh", "/tmp/steal.sh", "/usr/bin/aws"],
                Runs::Script("/tmp/steal.sh".into()),
            ),
            (
                &["busybox", "/bin/hush", "/tmp/steal.sh"],
                Runs::Script("/tmp/steal.sh".into()),
            ),
            (&["sh", "-c", "x", "/usr/bin/aws"], Runs::Code),
            (&["sh", "+c", "x"], Runs::Code),
            (&["sh", "-s"], Runs::Code),
            // a login shell, an interactive one
            (&["-sh"], Runs::Inline),
            (&["sh", "-i"], Runs::Inline),
            (&["sh", "--login"], Runs::Inline),
            // another program, busybox's own options
            (&["ls", "/tmp/steal.sh"], Runs::Inline),
            (&["busybox", "wget", "/tmp/steal.sh"], Runs::Inline),
            (&["busybox", "--list"], Runs::Inline),
            (&["busybox"], Runs::Inline),
        ] {
            let id = ExecIdentity::of_exec(bb, &argv(a));
            assert_eq!(id.runs, want, "{a:?}");
            assert!(!id.is_installed_program(), "{a:?}");
            assert!(!id.is_client(&["aws"]), "{a:?}");
        }
    }

    /// The program an inline option carries, as a record names it (R017):
    /// a shell's is its first operand after every option.
    #[test]
    fn the_inline_program_is_read_by_the_same_table() {
        let p = |exe: &str, a: &[&str]| {
            let a = argv(a);
            inline_program(Path::new(exe), &a).map(str::to_string)
        };
        assert_eq!(p("/bin/sh", &["sh", "-c", "id"]).as_deref(), Some("id"));
        assert_eq!(p("/bin/sh", &["sh", "-ec", "id"]).as_deref(), Some("id"));
        assert_eq!(
            p("/bin/bash", &["bash", "-c", "-e", "id"]).as_deref(),
            Some("id")
        );
        assert_eq!(
            p("/bin/bash", &["bash", "-co", "pipefail", "id"]).as_deref(),
            Some("id")
        );
        assert_eq!(
            p("/bin/bash", &["bash", "-c", "--", "id"]).as_deref(),
            Some("id")
        );
        assert_eq!(
            p("/usr/bin/python3", &["python3", "-Ic", "x=1"]).as_deref(),
            Some("x=1")
        );
        assert_eq!(
            p("/usr/bin/python3", &["python3", "-cx=1"]).as_deref(),
            Some("x=1")
        );
        assert_eq!(
            p("/usr/bin/perl", &["perl", "-le", "print"]).as_deref(),
            Some("print")
        );
        assert_eq!(
            p("/usr/bin/node", &["node", "--eval=x()"]).as_deref(),
            Some("x()")
        );
        assert_eq!(
            p("/usr/bin/node", &["node", "--print", "x()"]).as_deref(),
            Some("x()")
        );
        // none: standard input, a script, `-c` with no program, a binary
        assert_eq!(p("/bin/sh", &["sh", "-s", "id"]), None);
        assert_eq!(p("/bin/sh", &["sh", "/tmp/x"]), None);
        assert_eq!(p("/bin/sh", &["sh", "-c"]), None);
        assert_eq!(p("/usr/bin/cat", &["cat", "-c", "x"]), None);
    }
}
