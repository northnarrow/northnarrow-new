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
    /// bash, dash and `sh`. Lot 310 (the review of #539): each its own
    /// table — bash's long options with one hyphen are bash's only (dash
    /// reads `-posix` as letters) — and `sh`, whose shell its name does not
    /// tell (tracepoint mode reads the caller's path), read with both: where
    /// they differ, what it runs is not known.
    Shell,
    /// zsh and the ksh family: the options common to every shell only.
    OtherShell,
    Mono,
    /// Lot 310: busybox, a binary of many programs: the one `argv[0]` names
    /// (`sh` when it is `/bin/sh`), or, after a name starting with
    /// `busybox` (busybox's `is_prefixed_with`), the next argument's — again
    /// and again (`busybox busybox sh`). Its shells (`sh`, `ash`, `hush`,
    /// `bash`) are read as shells; any other program is a binary
    /// ([`Runs::Inline`]: busybox is no interpreter by its executable,
    /// [`crate::posture::lineage::is_interpreter`]).
    Busybox,
}

/// The family of an interpreter `exe`, by basename and a version suffix of
/// digits and dots (`python3.12`, `perl5.36`), or (lot 310, BUG-104) one of
/// the names the kernel resolves an interpreter's usual name to
/// (`/usr/bin/mono` is a link to `mono-sgen`, Alpine's `/bin/sh` one to
/// `busybox`, `busybox.static`); `None` for any other executable.
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
    /// runtimes (upstream's install and Debian's alternatives).
    const RESOLVED: &[(&str, Family)] =
        &[("mono-sgen", Family::Mono), ("mono-boehm", Family::Mono)];
    if let Some((_, family)) = RESOLVED.iter().find(|(name, _)| base == *name) {
        return Some(*family);
    }
    if base.starts_with("busybox") {
        return Some(Family::Busybox);
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
    /// Lot 310: no argument, and the interpreter runs no program with it —
    /// it prints and exits (`--version`, `-h`), only checks the program's
    /// syntax (`perl -c`, `node -c`, `ruby -c`) or reads without executing
    /// (a shell's `-n`, bash's `-D`): what it runs is [`Runs::Unknown`].
    NoRun,
    /// The rest of its argument, possibly empty (`perl -x`, `ruby -i.bak`).
    Rest,
    /// Lot 310 (the review of #539, finding 1): perl's `-i`, `-F`, `-C`:
    /// their value runs to the first whitespace, and perl reads switches
    /// again after a space (`perl.c`, `moreswitches`: `'-i -e CODE'` in one
    /// argument is `-i` then `-e CODE`).
    UntilSpace,
    /// Perl's `-D`: its value is the word characters after it.
    WordChars,
    /// The octal digits after it, then more letters (`perl -l`, `-0777`,
    /// `ruby -T`).
    Digits,
    /// The rest of its argument, else the next argument (`python -W
    /// ignore`, `-Wignore`, zsh's `-ovi`).
    Arg,
    /// Lot 310 (finding 2): [`Opt::Arg`] that loads the caller's code
    /// before the program (`node -r`, `ruby -r`, `-I`, `perl -I`): the
    /// program named is not all that runs ([`Runs::Unknown`]).
    Loads,
    /// The rest of its argument, which must not be empty, loading code
    /// (`perl -MFoo`, `-mFoo`: perl refuses `-M` alone).
    LoadsRest,
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
    /// letters (`perl -de 0`). The debugger (`perl5db.pl`, or `Devel::X`)
    /// runs commands of its own: it loads code (lot 310).
    PerlDebug,
}

/// How a long option is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Long {
    /// No argument (with `=value`, the value is its own: `node
    /// --inspect=9229`).
    Flag,
    /// Lot 310: no program runs ([`Opt::NoRun`]).
    NoRun,
    /// It takes the next argument, unless written `--name=value`.
    Arg,
    /// Lot 310 (finding 2): [`Long::Arg`] that loads the caller's code
    /// (`node --require`, `--import`, `--loader`, `--env-file`).
    Loads,
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
    /// Lot 310 (finding 1): perl reads switches again after a space inside
    /// one argument (a space, then `-`, then more switches; anything else
    /// ends the argument). Any other family: whitespace in a cluster is no
    /// option it has ([`Runs::Unknown`]).
    space_continues: bool,
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
        ("bBdEiIOPqsSuvxRtU3", Opt::Flag),
        ("hV?", Opt::NoRun),
        ("WXQ", Opt::Arg),
        ("c", Opt::Code),
        ("m", Opt::Module),
    ],
    long: &[
        ("help", Long::NoRun),
        ("help-all", Long::NoRun),
        ("help-env", Long::NoRun),
        ("help-xoptions", Long::NoRun),
        ("version", Long::NoRun),
        ("check-hash-based-pycs", Long::Arg),
    ],
    long_prefixes: &[],
    words: false,
    underscores: false,
    plus: false,
    space_continues: false,
    dash: Dash::Stdin,
};

/// perlrun, as `perl.c` reads it (`moreswitches`, `parse_body`); perl reads
/// `--help` and `--version` and refuses any other long option.
const PERL: Table = Table {
    short: &[
        ("afgnpsStTuUwWX", Opt::Flag),
        ("cvhV?", Opt::NoRun),
        ("l0", Opt::Digits),
        ("iFC", Opt::UntilSpace),
        ("D", Opt::WordChars),
        ("x", Opt::Rest),
        ("mM", Opt::LoadsRest),
        ("d", Opt::PerlDebug),
        ("I", Opt::Loads),
        ("eE", Opt::Code),
    ],
    long: &[("help", Long::NoRun), ("version", Long::NoRun)],
    long_prefixes: &[],
    words: false,
    underscores: false,
    plus: false,
    space_continues: true,
    dash: Dash::Stdin,
};

/// `ruby.c` (`proc_options`). `-v` prints the version and runs the script
/// if one is given.
const RUBY: Table = Table {
    short: &[
        ("apndyvwslSU", Opt::Flag),
        ("hc", Opt::NoRun),
        ("rI", Opt::Loads),
        ("CXE", Opt::Arg),
        ("ixF", Opt::Rest),
        ("0T", Opt::Digits),
        ("K", Opt::OneChar),
        ("W", Opt::RubyWarn),
        ("e", Opt::Code),
    ],
    long: &[
        ("copyright", Long::NoRun),
        ("version", Long::NoRun),
        ("help", Long::NoRun),
        ("verbose", Long::Flag),
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
    space_continues: false,
    dash: Dash::Stdin,
};

/// node's own options (its `node_options.cc`, v18–v24; V8's flags read
/// with `_` or `-`). One that takes a value takes the next argument unless
/// it is written `--name=value`; `--no-…` negates a flag. `-pe` is `-p`:
/// inline. Lot 310 (N3): `--run <task>` runs a task of the working
/// directory's `package.json` — the caller's, no file it names. Lot 310
/// (the review of #539): a preload (`-r`, `--require`, `--import`,
/// `--loader`), an environment file (`--env-file`: its `NODE_OPTIONS`), an
/// OpenSSL configuration (it loads engines), a snapshot or a configuration
/// file loads the caller's code ([`Long::Loads`]).
const NODE: Table = Table {
    short: &[
        ("i", Opt::Flag),
        ("cvh", Opt::NoRun),
        ("r", Opt::Loads),
        ("C", Opt::Arg),
        ("ep", Opt::Code),
    ],
    long: &[
        ("eval", Long::Code),
        ("print", Long::Code),
        ("run", Long::Code),
        ("require", Long::Loads),
        ("import", Long::Loads),
        ("loader", Long::Loads),
        ("experimental-loader", Long::Loads),
        ("conditions", Long::Arg),
        ("input-type", Long::Arg),
        ("env-file", Long::Loads),
        ("env-file-if-exists", Long::Loads),
        ("title", Long::Arg),
        ("inspect-port", Long::Arg),
        ("debug-port", Long::Arg),
        ("inspect-publish-uid", Long::Arg),
        ("icu-data-dir", Long::Arg),
        ("openssl-config", Long::Loads),
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
        ("experimental-config-file", Long::Loads),
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
        ("snapshot-blob", Long::Loads),
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
        ("help", Long::NoRun),
        ("version", Long::NoRun),
        ("v8-options", Long::NoRun),
        ("completion-bash", Long::NoRun),
        ("interactive", Long::Flag),
        ("check", Long::NoRun),
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
        ("prof-process", Long::NoRun),
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
    space_continues: false,
    dash: Dash::Stdin,
};

/// bash's `shell.c` (5.2): the `set` flags, `-i`, `-l`, `-r`, `-s`, `-c`,
/// `-D` (dump strings, no run); `-o` and `-O` take the next argument
/// (`-ovi` is `-o` then `-v -i`); `-c` and `-s` with either sign. Its long
/// options (`long_args`), with one hyphen or two, before the first cluster
/// ([`Table::words`]).
const BASH: Table = Table {
    short: &[
        ("abefhiklmprtuvxBCEHPT", Opt::Flag),
        ("nD", Opt::NoRun),
        ("oO", Opt::Next),
        ("c", Opt::ShellCode),
        ("s", Opt::Stdin),
    ],
    long: &[
        ("debug", Long::Flag),
        ("debugger", Long::Flag),
        ("login", Long::Flag),
        ("noediting", Long::Flag),
        ("noprofile", Long::Flag),
        ("norc", Long::Flag),
        ("posix", Long::Flag),
        ("restricted", Long::Flag),
        ("verbose", Long::Flag),
        ("help", Long::NoRun),
        ("version", Long::NoRun),
        ("dump-po-strings", Long::NoRun),
        ("dump-strings", Long::NoRun),
        ("pretty-print", Long::NoRun),
        ("init-file", Long::Arg),
        ("rcfile", Long::Arg),
    ],
    long_prefixes: &[],
    words: true,
    underscores: false,
    plus: true,
    space_continues: false,
    dash: Dash::EndOfOptions,
};

/// dash's `options.c` (0.5.12): its option letters (`-I` ignoreeof, `-V`
/// vi, `-E` emacs …), `-o` the next argument, `-c`, `-s`, `-l`; no long
/// option (`-posix` is `-p -o six`: `-o` takes the next argument as its
/// name). Lot 310 (the review of #539, finding 10): it had bash's table.
const DASH: Table = Table {
    short: &[
        ("abeflimpuvxCEIV", Opt::Flag),
        ("n", Opt::NoRun),
        ("o", Opt::Next),
        ("c", Opt::ShellCode),
        ("s", Opt::Stdin),
    ],
    long: &[],
    long_prefixes: &[],
    words: false,
    underscores: false,
    plus: true,
    space_continues: false,
    dash: Dash::EndOfOptions,
};

/// busybox's ash and hush (`ash.c`, `options`): dash's letters, `+c` read
/// as `-c`, and one long option, `--login`.
const BUSYBOX_ASH: Table = Table {
    short: DASH.short,
    long: &[("login", Long::Flag)],
    long_prefixes: &[],
    words: false,
    underscores: false,
    plus: true,
    space_continues: false,
    dash: Dash::EndOfOptions,
};

/// zsh and the ksh family: what every shell reads the same way, and `-o`
/// with its name attached or next (zsh(1): `-xoshwordsplit` is `-x -o
/// shwordsplit`; ksh's getopt). Lot 310 (BUG-100): it had bash's arity.
const OTHER_SHELL: Table = Table {
    short: &[
        ("aefhilmuvxC", Opt::Flag),
        ("n", Opt::NoRun),
        ("o", Opt::Arg),
        ("c", Opt::ShellCode),
        ("s", Opt::Stdin),
    ],
    long: &[],
    long_prefixes: &[],
    words: false,
    underscores: false,
    plus: true,
    space_continues: false,
    dash: Dash::Unknown,
};

/// mono(1).
const MONO: Table = Table {
    short: &[("v", Opt::Flag), ("Vh", Opt::NoRun)],
    long: &[
        ("debug", Long::Flag),
        ("verbose", Long::Flag),
        ("server", Long::Flag),
        ("desktop", Long::Flag),
        ("llvm", Long::Flag),
        ("nollvm", Long::Flag),
        ("version", Long::NoRun),
        ("help", Long::NoRun),
        ("config", Long::Arg),
    ],
    long_prefixes: &[],
    words: false,
    underscores: false,
    plus: false,
    space_continues: false,
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
    let r = reading(exe, argv);
    if r.runs != Runs::Code {
        return None;
    }
    let (at, from) = r.code?;
    argv.get(at)?.get(from..)
}

/// What one argv reads as.
#[derive(Debug, PartialEq, Eq)]
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
    let base = |a: &str| a.rsplit('/').next().unwrap_or(a).to_string();
    let table = match family_of(exe) {
        None => return Runs::Inline.into(),
        Some(Family::Python) => &PYTHON,
        Some(Family::Perl) => &PERL,
        Some(Family::Ruby) => &RUBY,
        Some(Family::Node) => &NODE,
        Some(Family::OtherShell) => &OTHER_SHELL,
        Some(Family::Mono) => &MONO,
        Some(Family::Shell) => {
            let name = exe.file_name().map(|n| n.to_string_lossy().into_owned());
            match name.as_deref() {
                Some(n) if n.starts_with("bash") => &BASH,
                Some(n) if n.starts_with("dash") => &DASH,
                // `sh`: bash or dash, the name does not tell; both must read
                // it alike
                _ => {
                    let (b, d) = (read(&BASH, argv, 1), read(&DASH, argv, 1));
                    if b == d {
                        return b;
                    }
                    return Runs::Unknown(guess(argv, 1, true)).into();
                }
            }
        }
        Some(Family::Busybox) => {
            // busybox's `main`: the program `argv[0]` names (a login
            // shell's `-` dropped); a name starting with `busybox` is
            // busybox itself (`is_prefixed_with`), and the next argument
            // names the program — one starting with `-` is busybox's own
            // option (`--list`, `--help`)
            let Some(first) = argv.first() else {
                return Runs::Inline.into();
            };
            let mut at = 0;
            let mut program = base(first.strip_prefix('-').unwrap_or(first));
            while program.starts_with("busybox") {
                match argv.get(at + 1) {
                    Some(a) if !a.starts_with('-') => {
                        at += 1;
                        program = base(a);
                    }
                    _ => return Runs::Inline.into(),
                }
            }
            if !BUSYBOX_SHELLS.contains(&program.as_str()) {
                return Runs::Inline.into();
            }
            return read(&BUSYBOX_ASH, argv, at + 1);
        }
    };
    read(table, argv, 1)
}

/// What the options seen so far change in what an interpreter runs (lot
/// 310): a preload of the caller's code, or a program that does not run.
#[derive(Default)]
struct Seen {
    loads: bool,
    no_run: bool,
}

impl Seen {
    /// The reading, with what the options said: no program runs →
    /// [`Runs::Unknown`]; the caller's code loaded before a named script →
    /// [`Runs::Unknown`] (the script kept for a record), before nothing
    /// named → [`Runs::Code`].
    fn finish(&self, r: Reading) -> Reading {
        if self.no_run {
            return match r.runs {
                Runs::Script(s) => Runs::Unknown(Some(s)).into(),
                Runs::Unknown(s) => Runs::Unknown(s).into(),
                Runs::Inline | Runs::Code => Runs::Unknown(None).into(),
            };
        }
        if self.loads {
            return match r.runs {
                Runs::Script(s) => Runs::Unknown(Some(s)).into(),
                Runs::Inline => Runs::Code.into(),
                Runs::Code | Runs::Unknown(_) => r,
            };
        }
        r
    }
}

/// The one reader: `argv` from `from` on, through `table`.
fn read(table: &Table, argv: &[String], from: usize) -> Reading {
    let mut seen = Seen::default();
    let r = read_options(table, argv, from, &mut seen);
    seen.finish(r)
}

fn read_options(table: &Table, argv: &[String], from: usize, seen: &mut Seen) -> Reading {
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
                    Some(Long::NoRun) => {
                        seen.no_run = true;
                        continue;
                    }
                    Some(Long::Arg | Long::Loads) => {
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
                Some(Long::NoRun) => {
                    seen.no_run = true;
                    continue;
                }
                Some(long @ (Long::Arg | Long::Loads)) => {
                    if value.is_none() {
                        if argv.get(i).is_none() {
                            return unknown();
                        }
                        i += 1;
                    }
                    seen.loads |= long == Long::Loads;
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
            if c.is_whitespace() {
                // perl: a space, then `-` and more switches; anything else
                // ends the argument (`moreswitches`, case ' '). A tab or a
                // newline perl refuses; any other family has no such option
                if table.space_continues && c == ' ' {
                    match rest.trim_start_matches(' ').strip_prefix('-') {
                        Some(more) => {
                            pos = letters.len() - more.len();
                            continue;
                        }
                        None => break,
                    }
                }
                return unknown();
            }
            let Some(opt) = table.short(c) else {
                return unknown();
            };
            match opt {
                Opt::Flag => {}
                Opt::NoRun => seen.no_run = true,
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
                Opt::LoadsRest if rest.is_empty() => return unknown(),
                Opt::LoadsRest => {
                    seen.loads = true;
                    break;
                }
                Opt::UntilSpace => pos += rest.find(char::is_whitespace).unwrap_or(rest.len()),
                Opt::WordChars => {
                    pos += rest
                        .bytes()
                        .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
                        .count()
                }
                Opt::Arg | Opt::Loads | Opt::Module => {
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
                    seen.loads |= opt == Opt::Loads;
                    break;
                }
                // Perl's `-0x1F`: the `x` then reads as `-x`, which takes
                // the rest, as the hexadecimal digits would
                Opt::Digits => pos += octal_digits(rest),
                Opt::OneChar => pos += rest.chars().next().map_or(0, char::len_utf8),
                Opt::RubyWarn if rest.starts_with(':') => break,
                Opt::RubyWarn => pos += octal_digits(rest).min(1),
                Opt::PerlDebug => {
                    seen.loads = true;
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
            &["bash", "-debug", "-noediting", "/tmp/steal.sh"],
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
        // a preload: the script read, but not all that runs (lot 310, the
        // review of #539)
        assert_eq!(
            runs_of(
                node,
                &argv(&["node", "--require=/usr/lib/x.js", "/tmp/e.js"])
            ),
            Runs::Unknown(Some("/tmp/e.js".into()))
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
            // the review of #539 (finding 11): a program of busybox that
            // names nothing is the installed binary (it was "no installed
            // program" for every form); a script or an inline program never
            assert_eq!(id.is_installed_program(), want == Runs::Inline, "{a:?}");
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
    // ── Lot 310, the independent review of #539 ─────────────────────────

    /// Finding 1: perl reads switches again after a space inside one
    /// argument, and `-i`, `-F`, `-C` end at whitespace, `-D` at a non-word
    /// character (`perl.c`: `moreswitches`). `perl '-i -e CODE' /usr/bin/aws`
    /// runs CODE: it read as the `aws` script. Checked with perl 5.38.2.
    #[test]
    fn review_perl_switches_after_a_space_in_one_argument() {
        use crate::posture::lineage::ExecIdentity;
        for a in [
            "-i -e x()",
            "-i.bak -e x()",
            "-F: -e x()",
            "-CSD -e x()",
            "-C -e x()",
            "-D -e x()",
            "-Dx -e x()",
            "-w -e x()",
            "-wl -e x()",
            "- -e x()",
            "-i  -e x()",
        ] {
            let id = ExecIdentity::of_exec("/usr/bin/perl", &argv(&["perl", a, "/usr/bin/aws"]));
            assert_eq!(id.runs, Runs::Code, "{a:?}");
            assert!(
                !id.is_client(&["aws"]) && !id.is_installed_program(),
                "{a:?}"
            );
        }
        // a space then no `-`: the rest of the argument is ignored
        assert_eq!(
            runs_of(
                Path::new("/usr/bin/perl"),
                &argv(&["perl", "-i x", "/tmp/s"])
            ),
            Runs::Script("/tmp/s".into())
        );
        // a tab perl refuses; whitespace in any other family's cluster is no
        // option of its
        for (exe, a) in [
            ("/usr/bin/perl", "-i\t-e x()"),
            ("/usr/bin/python3", "-O -c x()"),
            ("/usr/bin/ruby", "-w -e x()"),
            ("/usr/bin/bash", "-e -c x"),
            ("/usr/bin/node", "-i -e x"),
        ] {
            let a = a.replace("\\t", "\t");
            let got = runs_of(Path::new(exe), &argv(&["x", &a, "/usr/bin/aws"]));
            assert!(matches!(got, Runs::Unknown(_)), "{exe} {a:?}: {got:?}");
        }
    }

    /// Finding 2: an option that loads the caller's code before the script
    /// (`node -r`, `--require`, `--import`, `--loader`, `--env-file`; perl
    /// `-M`, `-m`, `-I`, `-d`; ruby `-r`, `-I`) leaves the script named but
    /// not all that runs: no client, no installed program. Node 18 runs
    /// `--require /tmp/x.js` before the named script.
    #[test]
    fn review_a_preload_is_not_the_named_program() {
        use crate::posture::lineage::ExecIdentity;
        for (exe, a) in [
            (
                "/usr/bin/node",
                &["node", "--require", "/tmp/x.js", "/usr/bin/aws"][..],
            ),
            (
                "/usr/bin/node",
                &["node", "-r", "/tmp/x.js", "/usr/bin/aws"],
            ),
            ("/usr/bin/node", &["node", "-r/tmp/x.js", "/usr/bin/aws"]),
            (
                "/usr/bin/node",
                &["node", "--import=data:text/javascript,x", "/usr/bin/aws"],
            ),
            (
                "/usr/bin/node",
                &["node", "--loader", "/tmp/l.mjs", "/usr/bin/aws"],
            ),
            (
                "/usr/bin/node",
                &["node", "--experimental-loader=/tmp/l.mjs", "/usr/bin/aws"],
            ),
            (
                "/usr/bin/node",
                &["node", "--env-file=/tmp/e", "/usr/bin/aws"],
            ),
            (
                "/usr/bin/node",
                &["node", "--openssl-config", "/tmp/c", "/usr/bin/aws"],
            ),
            ("/usr/bin/perl", &["perl", "-MEvil", "/usr/bin/aws"]),
            ("/usr/bin/perl", &["perl", "-mEvil", "/usr/bin/aws"]),
            ("/usr/bin/perl", &["perl", "-I/tmp", "/usr/bin/aws"]),
            ("/usr/bin/perl", &["perl", "-d:Evil", "/usr/bin/aws"]),
            ("/usr/bin/perl", &["perl", "-d", "/usr/bin/aws"]),
            ("/usr/bin/ruby", &["ruby", "-r/tmp/x", "/usr/bin/aws"]),
            ("/usr/bin/ruby", &["ruby", "-I", "/tmp", "/usr/bin/aws"]),
        ] {
            let id = ExecIdentity::of_exec(exe, &argv(a));
            assert_eq!(id.runs, Runs::Unknown(Some("/usr/bin/aws".into())), "{a:?}");
            assert!(
                !id.is_client(&["aws"]) && !id.is_installed_program(),
                "{a:?}"
            );
        }
        // a preload before nothing named: the caller's code
        assert_eq!(
            runs_of(
                Path::new("/usr/bin/node"),
                &argv(&["node", "-r", "/tmp/x.js"])
            ),
            Runs::Code
        );
        // an option with a value that loads nothing keeps the script
        assert_eq!(
            runs_of(
                Path::new("/usr/bin/node"),
                &argv(&["node", "--title", "x", "/usr/bin/aws"])
            ),
            Runs::Script("/usr/bin/aws".into())
        );
    }

    /// An option with which no program runs (it prints and exits, checks the
    /// syntax only, or reads without executing) runs nothing: not known.
    #[test]
    fn review_an_option_that_runs_nothing_is_not_known() {
        for (exe, a) in [
            ("/usr/bin/bash", &["bash", "-n", "/tmp/s"][..]),
            ("/usr/bin/bash", &["bash", "--version"]),
            ("/usr/bin/bash", &["bash", "-pretty-print", "/tmp/s"]),
            ("/usr/bin/bash", &["bash", "-D", "/tmp/s"]),
            ("/usr/bin/dash", &["sh", "-n", "/tmp/s"]),
            ("/usr/bin/python3", &["python3", "-V"]),
            ("/usr/bin/python3", &["python3", "--help", "/tmp/s"]),
            ("/usr/bin/perl", &["perl", "-c", "/tmp/s"]),
            ("/usr/bin/perl", &["perl", "-v"]),
            ("/usr/bin/node", &["node", "--check", "/tmp/s"]),
            ("/usr/bin/node", &["node", "-v"]),
            ("/usr/bin/ruby", &["ruby", "-c", "/tmp/s"]),
            ("/usr/bin/ruby", &["ruby", "--version"]),
        ] {
            let got = runs_of(Path::new(exe), &argv(a));
            assert!(matches!(got, Runs::Unknown(_)), "{a:?}: {got:?}");
        }
        // ruby's -v prints the version and runs the script given
        assert_eq!(
            runs_of(Path::new("/usr/bin/ruby"), &argv(&["ruby", "-v", "/tmp/s"])),
            Runs::Script("/tmp/s".into())
        );
    }

    /// Finding 10: dash has no long options — `sh -posix vi -c CODE` is `-p`,
    /// `-o` (taking `vi`), `-s`, `-i`, `-x`, then `-c`: dash runs CODE (dash
    /// 0.5.12). bash reads `-posix` as its long option. `sh`, whose shell its
    /// name does not tell, is read by both: where they differ, not known.
    #[test]
    fn review_dash_is_not_read_with_bash_s_long_options() {
        let a = argv(&["sh", "-posix", "vi", "-c", "x"]);
        assert_eq!(runs_of(Path::new("/usr/bin/dash"), &a), Runs::Code);
        assert_eq!(
            runs_of(Path::new("/usr/bin/bash"), &a),
            Runs::Script("vi".into())
        );
        assert!(matches!(
            runs_of(Path::new("/bin/sh"), &a),
            Runs::Unknown(_)
        ));
        // where they agree, the reading stands
        assert_eq!(
            runs_of(Path::new("/bin/sh"), &argv(&["sh", "-e", "/tmp/s"])),
            Runs::Script("/tmp/s".into())
        );
        assert_eq!(
            runs_of(Path::new("/bin/sh"), &argv(&["sh", "-c", "x"])),
            Runs::Code
        );
        // dash refuses bash's words: `-norc` is letters there
        assert!(!matches!(
            runs_of(
                Path::new("/usr/bin/dash"),
                &argv(&["sh", "-norc", "/tmp/s"])
            ),
            Runs::Script(_)
        ));
    }

    /// Finding 11: busybox runs busybox's own `main` for any name starting
    /// with `busybox` (`busybox.static`, `busybox busybox sh`); its other
    /// programs are the installed binary they are (a `busybox httpd` on a
    /// common port keeps the installed program's exemption).
    #[test]
    fn review_busybox_names_and_programs() {
        use crate::posture::lineage::ExecIdentity;
        for (exe, a) in [
            ("/bin/busybox", &["busybox", "busybox", "sh", "-c", "x"][..]),
            ("/bin/busybox", &["busybox.static", "sh", "-c", "x"]),
            ("/bin/busybox.static", &["busybox.static", "ash", "-c", "x"]),
            ("/bin/busybox", &["busyboxX", "sh", "-c", "x"]),
        ] {
            let id = ExecIdentity::of_exec(exe, &argv(a));
            assert_eq!(id.runs, Runs::Code, "{a:?}");
            assert!(id.interprets() && !id.is_installed_program(), "{a:?}");
        }
        for a in [
            &["wget", "http://x"][..],
            &["busybox", "httpd", "-p", "80"],
            &["httpd"],
        ] {
            let id = ExecIdentity::of_exec("/bin/busybox", &argv(a));
            assert_eq!(id.runs, Runs::Inline, "{a:?}");
            assert!(!id.interprets() && id.is_installed_program(), "{a:?}");
        }
        assert!(!crate::posture::lineage::is_interpreter(Path::new(
            "/bin/busybox"
        )));
    }
}
