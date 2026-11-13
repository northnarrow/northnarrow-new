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
    /// Lot 313 (the review of #549, F4): the dynamic loader run as a
    /// program (`/lib64/ld-linux-x86-64.so.2 [options] /bin/bash -i`): the
    /// kernel executed the loader, which runs the program its first operand
    /// names — what the process is ([`Runs::Script`]), as an interpreter's
    /// script is.
    Loader,
}

/// Lot 313 (F4): the dynamic loader's names — glibc's (`ld-linux-x86-64.so.2`,
/// `ld-linux-aarch64.so.1`, `ld-linux.so.2`, `ld64.so.2`, `ld.so`) and musl's
/// (`ld-musl-x86_64.so.1`).
pub(crate) fn is_loader_name(base: &str) -> bool {
    ((base.starts_with("ld-linux") || base.starts_with("ld-musl-") || base.starts_with("ld64."))
        && base.contains(".so"))
        || base == "ld.so"
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
    if is_loader_name(&base) {
        return Some(Family::Loader);
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
    /// Ruby's `-v`: the version printed, then the script run — with none,
    /// nothing runs ([`Runs::Unknown`]).
    NoRunAlone,
    /// Python's `-i` (and ruby's `-s`, whose script arguments set its
    /// globals): after the program, the interpreter reads its standard
    /// input and runs it (a terminal's user, or a file, a pipe: `python3 -i
    /// /usr/bin/x < code`) — a script named is not all that runs
    /// ([`Runs::Unknown`]); with nothing named it is the interactive
    /// interpreter, as without it (the differential test of #539's review).
    Inspect,
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
    /// Lot 310 (the review of #539, finding 11): the names a shell's `-o`
    /// (and bash's `-O`) take — another one it refuses, and nothing runs
    /// ([`Runs::Unknown`]). The names every supported version has; one only
    /// some have (dash's `pipefail`) is not known either.
    names: &'static [(char, &'static [&'static str])],
    /// The values a long option takes, when it has a list (python's
    /// `--check-hash-based-pycs`): another one it refuses, and nothing runs.
    long_names: &'static [(&'static str, &'static [&'static str])],
    /// perl, ruby and node: after `-e CODE` the options go on (`perl -e A
    /// -e B -n`, `-e A -c`, `node -p A --version`), up to the program's
    /// arguments; any other family ends its options with the program.
    code_continues: bool,
    /// node and ruby: an option's value in the next argument never starts
    /// with `-` (node: "--title requires an argument"; ruby takes it and
    /// fails on it) — such an argv runs nothing.
    arg_not_dash: bool,
    /// The options whose value is a word — never a path, never empty
    /// (ruby's `-E` encoding): another value the interpreter refuses.
    word_values: &'static str,
    /// A `+c` cluster runs its program as `-c` does (bash, dash, busybox's
    /// ash); for the ksh family and zsh it is no option to rely on.
    plus_code: bool,
    /// The values of an option that load code (python's `-X
    /// pycache_prefix=DIR`: bytecode read from the caller's directory; `-X
    /// presite=MOD`): by prefix (the re-check of #539, N4).
    loading_values: &'static [(char, &'static [&'static str])],
    /// What a lone `-` means.
    dash: Dash,
}

impl Table {
    /// `value` is one long option `name` takes; `true` for one with no list.
    fn long_value_ok(&self, name: &str, value: &str) -> bool {
        self.long_names
            .iter()
            .find(|(n, _)| *n == name)
            .is_none_or(|(_, values)| values.contains(&value))
    }

    /// `value` is a name option `c` takes; `true` for an option with no list.
    fn names_ok(&self, c: char, value: &str) -> bool {
        match self.names.iter().find(|(o, _)| *o == c) {
            None => true,
            Some((_, names)) => {
                let v = value.to_ascii_lowercase();
                names.contains(&v.as_str()) || names.contains(&v.replace('_', "").as_str())
            }
        }
    }

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
        ("bBdEIOPqsSuvxRtU3", Opt::Flag),
        ("i", Opt::Inspect),
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
    names: &[],
    long_names: &[("check-hash-based-pycs", &["default", "always", "never"])],
    code_continues: false,
    arg_not_dash: false,
    word_values: "",
    plus_code: false,
    loading_values: &[('X', &["pycache_prefix", "presite"])],
    dash: Dash::Stdin,
};

/// perlrun, as `perl.c` reads it (`moreswitches`, `parse_body`); perl reads
/// `--help` and `--version` and refuses any other long option.
const PERL: Table = Table {
    short: &[
        ("afgnpsStTUwWX", Opt::Flag),
        // `-u` dumps core after compiling: the program does not run
        ("cuvhV?", Opt::NoRun),
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
    names: &[],
    long_names: &[],
    code_continues: true,
    arg_not_dash: false,
    word_values: "",
    plus_code: false,
    loading_values: &[],
    dash: Dash::Stdin,
};

/// `ruby.c` (`proc_options`). `-v` prints the version and runs the script
/// if one is given.
const RUBY: Table = Table {
    short: &[
        ("apndywlSU", Opt::Flag),
        // `-s`: the script's arguments set its globals (one it refuses
        // stops it): the script named is not all that decides what runs
        ("s", Opt::Inspect),
        ("v", Opt::NoRunAlone),
        ("hc", Opt::NoRun),
        // `-C dir`, `-X dir`: the script named is read from another
        // directory
        ("rICX", Opt::Loads),
        ("E", Opt::Arg),
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
    names: &[],
    long_names: &[],
    code_continues: true,
    arg_not_dash: true,
    word_values: "E",
    plus_code: false,
    loading_values: &[],
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
        // the reporter is a module node loads into the process (the re-check
        // of #539, N4: `--test --test-reporter=/tmp/r.mjs /usr/bin/aws`)
        ("test-reporter", Long::Loads),
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
    names: &[],
    long_names: &[],
    code_continues: true,
    arg_not_dash: true,
    word_values: "",
    plus_code: false,
    loading_values: &[],
    dash: Dash::Stdin,
};

/// bash 5.2's `set -o` names.
const BASH_SET_O: &[&str] = &[
    "allexport",
    "braceexpand",
    "emacs",
    "errexit",
    "errtrace",
    "functrace",
    "hashall",
    "histexpand",
    "history",
    "ignoreeof",
    "interactive-comments",
    "keyword",
    "monitor",
    "noclobber",
    "noexec",
    "noglob",
    "nolog",
    "notify",
    "nounset",
    "onecmd",
    "physical",
    "pipefail",
    "posix",
    "privileged",
    "verbose",
    "vi",
    "xtrace",
];

/// bash 5.2's `shopt` names (`-O`).
const BASH_SHOPT: &[&str] = &[
    "assoc_expand_once",
    "autocd",
    "cdable_vars",
    "cdspell",
    "checkhash",
    "checkjobs",
    "checkwinsize",
    "cmdhist",
    "compat31",
    "compat32",
    "compat40",
    "compat41",
    "compat42",
    "compat43",
    "compat44",
    "complete_fullquote",
    "direxpand",
    "dirspell",
    "dotglob",
    "execfail",
    "expand_aliases",
    "extdebug",
    "extglob",
    "extquote",
    "failglob",
    "force_fignore",
    "globasciiranges",
    "globskipdots",
    "globstar",
    "gnu_errfmt",
    "histappend",
    "histreedit",
    "histverify",
    "hostcomplete",
    "huponexit",
    "inherit_errexit",
    "interactive_comments",
    "lastpipe",
    "lithist",
    "localvar_inherit",
    "localvar_unset",
    "login_shell",
    "mailwarn",
    "no_empty_cmd_completion",
    "nocaseglob",
    "nocasematch",
    "noexpand_translation",
    "nullglob",
    "patsub_replacement",
    "progcomp",
    "progcomp_alias",
    "promptvars",
    "restricted_shell",
    "shift_verbose",
    "sourcepath",
    "varredir_close",
    "xpg_echo",
];

/// dash's `set -o` names (0.5.12; `pipefail` came later: not known).
const DASH_SET_O: &[&str] = &[
    "errexit",
    "noglob",
    "ignoreeof",
    "interactive",
    "monitor",
    "noexec",
    "stdin",
    "xtrace",
    "verbose",
    "vi",
    "emacs",
    "noclobber",
    "allexport",
    "notify",
    "nounset",
    "privileged",
    "nolog",
];

/// busybox ash's `set -o` names (1.36).
const ASH_SET_O: &[&str] = &[
    "errexit",
    "noglob",
    "ignoreeof",
    "interactive",
    "monitor",
    "noexec",
    "stdin",
    "xtrace",
    "verbose",
    "vi",
    "emacs",
    "noclobber",
    "allexport",
    "notify",
    "nounset",
    "pipefail",
];

/// The `-o` names zsh, mksh and ksh93 all read (each has more: not known).
const OTHER_SET_O: &[&str] = &[
    "errexit",
    "noglob",
    "ignoreeof",
    "monitor",
    "noexec",
    "xtrace",
    "verbose",
    "vi",
    "emacs",
    "noclobber",
    "allexport",
    "notify",
    "nounset",
    "pipefail",
];

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
    names: &[('o', BASH_SET_O), ('O', BASH_SHOPT)],
    long_names: &[],
    code_continues: false,
    arg_not_dash: false,
    word_values: "",
    plus_code: true,
    loading_values: &[],
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
    names: &[('o', DASH_SET_O)],
    long_names: &[],
    code_continues: false,
    arg_not_dash: false,
    word_values: "",
    plus_code: true,
    loading_values: &[],
    dash: Dash::EndOfOptions,
};

/// busybox's ash and hush (`ash.c`, `options`): dash's letters, `+c` read
/// as `-c`, and one long option, `--login`.
const BUSYBOX_ASH: Table = Table {
    // busybox 1.36's ash: no `-p`, no `-V` (it refuses them)
    short: &[
        ("abeflimuvxCEI", Opt::Flag),
        ("n", Opt::NoRun),
        ("o", Opt::Next),
        ("c", Opt::ShellCode),
        ("s", Opt::Stdin),
    ],
    long: &[("login", Long::Flag)],
    long_prefixes: &[],
    words: false,
    underscores: false,
    plus: true,
    space_continues: false,
    names: &[('o', ASH_SET_O)],
    long_names: &[],
    code_continues: false,
    arg_not_dash: false,
    word_values: "",
    plus_code: true,
    loading_values: &[],
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
    names: &[('o', OTHER_SET_O)],
    long_names: &[],
    code_continues: false,
    arg_not_dash: false,
    word_values: "",
    plus_code: false,
    loading_values: &[],
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
    names: &[],
    long_names: &[],
    code_continues: false,
    arg_not_dash: false,
    word_values: "",
    plus_code: false,
    loading_values: &[],
    dash: Dash::Stdin,
};

/// Lot 313 (the review of #549, F4): glibc's `ld.so --help` (2.35–2.41)
/// and musl's: the options before the program; `--preload` and `--audit`
/// load the caller's code into it.
const LOADER: Table = Table {
    short: &[],
    long: &[
        ("library-path", Long::Arg),
        ("argv0", Long::Arg),
        ("inhibit-rpath", Long::Arg),
        ("glibc-hwcaps-prepend", Long::Arg),
        ("glibc-hwcaps-mask", Long::Arg),
        ("preload", Long::Loads),
        ("audit", Long::Loads),
        ("inhibit-cache", Long::Flag),
        ("verify", Long::Flag),
        ("list", Long::Flag),
        ("list-tunables", Long::NoRun),
        ("list-diagnostics", Long::NoRun),
        ("help", Long::NoRun),
        ("version", Long::NoRun),
    ],
    long_prefixes: &[],
    words: false,
    underscores: false,
    plus: false,
    space_continues: false,
    names: &[],
    long_names: &[],
    code_continues: false,
    arg_not_dash: false,
    word_values: "",
    plus_code: false,
    loading_values: &[],
    dash: Dash::Unknown,
};

/// Lot 313 (F4): the program the dynamic loader runs for `argv` (its first
/// operand past the loader's options, read with [`LOADER`]'s arities), and
/// where its own arguments start (its `argv[0]` is the loader's operand).
/// `None`: no program, or an option the table does not hold.
pub fn loader_program(argv: &[String]) -> Option<(&str, usize)> {
    let mut i = 1;
    while let Some(a) = argv.get(i) {
        if a == "--" {
            return argv.get(i + 1).map(|p| (p.as_str(), i + 1));
        }
        let Some(name) = a.strip_prefix("--") else {
            return (!a.starts_with('-')).then_some((a.as_str(), i));
        };
        let (name, value) = name
            .split_once('=')
            .map_or((name, false), |(n, _)| (n, true));
        match LOADER.long(name)? {
            Long::Arg | Long::Loads if !value => i += 2,
            Long::NoRun => return None,
            _ => i += 1,
        }
    }
    None
}

/// busybox's shells.
pub(crate) const BUSYBOX_SHELLS: &[&str] = &["sh", "ash", "hush", "bash"];

/// The program busybox runs for `argv`, and where its own arguments start
/// — as busybox reads it (`libbb/appletlib.c`, lot 313: one reading for the
/// interpreters' reader and R020's shells). `main` takes `argv[0]`, a login
/// shell's `-` dropped, then its basename; a name that starts with
/// `busybox` (`busybox`, `busybox.static`) is busybox itself, whose
/// `busybox_main` takes the next argument's basename (`busybox /bin/sh`),
/// and again while that one starts with `busybox` (`busybox busybox sh`).
/// `None`: busybox runs no program — no argument, or its own `--help`,
/// `--list…`, `--install`. Lot 310 read only `busybox` exactly, and once.
pub(crate) fn busybox_program(argv: &[String]) -> Option<(&str, usize)> {
    fn base(a: &str) -> &str {
        a.rsplit('/').next().unwrap_or(a)
    }
    let first = argv.first()?;
    let mut name = base(first.strip_prefix('-').unwrap_or(first));
    let mut at = 1;
    while name.starts_with("busybox") {
        let next = argv.get(at)?;
        if next == "--help" || next == "--install" || next.starts_with("--list") {
            return None;
        }
        name = base(next);
        at += 1;
    }
    Some((name, at))
}

/// What `exe` runs for `argv` (its `argv[0]` first): [`Runs`]. A binary
/// runs its executable ([`Runs::Inline`]).
pub(crate) fn runs_of(exe: &Path, argv: &[String]) -> Runs {
    reading(exe, argv).runs
}

/// Lot 310: the program an interpreter's argv carries inline (`-c CMD`,
/// `-e CODE`, `--eval=CODE`), for a record; `None` when it runs none, or
/// its options could not be read.
pub fn inline_program<'a>(exe: &Path, argv: &'a [String]) -> Option<&'a str> {
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

/// busybox's `main`: the program `argv[0]` names (a login shell's `-`
/// dropped); a name starting with `busybox` is busybox itself
/// (`is_prefixed_with`), and the next argument names the program — one
/// starting with `-` is busybox's own option (`--list`, `--help`). The
/// index of the argument naming one of its shells, `None` for another
/// program.
fn busybox_shell_at(argv: &[String]) -> Option<usize> {
    // lot 313: busybox's one reading (`busybox_program`), shared with R020
    let (program, from) = busybox_program(argv)?;
    BUSYBOX_SHELLS.contains(&program).then_some(from - 1)
}

/// A `/proc/<pid>/cmdline`'s arguments: its NUL-separated words, the
/// final NUL dropped and no other (lot 310: an empty argument is one —
/// `python3 -W '' /tmp/x.py /usr/bin/aws` runs `/tmp/x.py`; the review of
/// #539 found the empty words dropped in `ring_drops`, its re-check here).
pub fn argv_of_cmdline(cmdline: &[u8]) -> Vec<String> {
    let body = cmdline.strip_suffix(&[0]).unwrap_or(cmdline);
    if body.is_empty() {
        return Vec::new();
    }
    body.split(|b| *b == 0)
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect()
}

/// Lot 310 (the re-check of #539, N5): `NODE_OPTIONS` names an option
/// that loads code into node (`-r`, `--require`, `--import`, `--loader`,
/// `--experimental-loader`, `--test-reporter`: the node table's loading
/// options, written alone, with `=value` or `-rvalue`) — read with the node
/// table, so `--max-old-space-size` and its like load nothing. Node splits
/// the variable on whitespace; quotes are dropped.
pub fn node_options_load(options: &str) -> bool {
    options
        .split(|c: char| c.is_whitespace() || c == '"' || c == '\'')
        .filter(|w| !w.is_empty())
        .any(|w| match w.strip_prefix("--") {
            Some(long) => {
                let name = long.split_once('=').map_or(long, |(n, _)| n);
                NODE.long(name) == Some(Long::Loads)
            }
            None => w.strip_prefix('-').is_some_and(|cluster| {
                cluster
                    .chars()
                    .next()
                    .is_some_and(|c| matches!(NODE.short(c), Some(Opt::Loads | Opt::LoadsRest)))
            }),
        })
}

/// Lot 310 (the re-check of #539, N9): `exe` run as `argv` reads a program
/// its caller gives — any interpreter, or busybox running one of its
/// shells (`sh`, `busybox sh`): its standard input or its environment can
/// carry the caller's code. busybox's other programs read none.
pub fn reads_a_program(exe: &Path, argv: &[String]) -> bool {
    match family_of(exe) {
        None => false,
        Some(Family::Busybox) => busybox_shell_at(argv).is_some(),
        Some(_) => true,
    }
}

fn reading(exe: &Path, argv: &[String]) -> Reading {
    let table = match family_of(exe) {
        None => return Runs::Inline.into(),
        Some(Family::Python) => &PYTHON,
        Some(Family::Perl) => &PERL,
        Some(Family::Ruby) => &RUBY,
        Some(Family::Node) => &NODE,
        Some(Family::OtherShell) => &OTHER_SHELL,
        Some(Family::Mono) => &MONO,
        Some(Family::Loader) => &LOADER,
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
            return match busybox_shell_at(argv) {
                Some(at) => read(&BUSYBOX_ASH, argv, at + 1),
                None => Runs::Inline.into(),
            };
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
    /// Ruby's `-v`: nothing runs unless a program is named.
    no_run_alone: bool,
    /// Python's `-i`: the standard input runs after the program.
    inspect: bool,
}

impl Seen {
    /// The reading, with what the options said: no program runs →
    /// [`Runs::Unknown`]; the caller's code loaded before a named script →
    /// [`Runs::Unknown`] (the script kept for a record), before nothing
    /// named → [`Runs::Code`].
    fn finish(&self, r: Reading) -> Reading {
        if self.no_run_alone && r.runs == Runs::Inline {
            return Runs::Unknown(None).into();
        }
        if self.no_run {
            return match r.runs {
                Runs::Script(s) => Runs::Unknown(Some(s)).into(),
                Runs::Unknown(s) => Runs::Unknown(s).into(),
                Runs::Inline | Runs::Code => Runs::Unknown(None).into(),
            };
        }
        if self.inspect {
            if let Runs::Script(s) = r.runs {
                return Runs::Unknown(Some(s)).into();
            }
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
    // a shell's `-s`: its program is its standard input, its operands the
    // positional parameters
    let mut stdin = false;
    // perl's and ruby's first `-e`, the switches going on after it
    let mut code: Option<(usize, usize)> = None;
    while let Some(a) = argv.get(i) {
        i += 1;
        let unknown = move || Runs::Unknown(guess(argv, i, table.plus)).into();
        if a == "--" {
            // `python3 -- -`: the standard input's program still
            if table.dash == Dash::Stdin && code.is_none() && argv.get(i).is_some_and(|n| n == "-")
            {
                return Runs::Code.into();
            }
            return end(argv, i, shell_code, stdin, code);
        }
        if a == "-" {
            return match table.dash {
                Dash::EndOfOptions => end(argv, i, shell_code, stdin, code),
                // the program is the standard input (lot 310, the review's
                // differential test: it was taken for a script named `-`)
                Dash::Stdin if code.is_none() => Runs::Code.into(),
                Dash::Stdin => end(argv, i, shell_code, stdin, code),
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
                    let value = match value {
                        Some(v) => v,
                        None => {
                            let Some(v) = argv.get(i) else {
                                return unknown();
                            };
                            if table.arg_not_dash && v.starts_with('-') {
                                return unknown();
                            }
                            i += 1;
                            v.as_str()
                        }
                    };
                    if !table.long_value_ok(name, value) {
                        return unknown();
                    }
                    seen.loads |= long == Long::Loads;
                    continue;
                }
                Some(Long::Code) => {
                    let at = match value {
                        Some(v) => (i - 1, a.len() - v.len()),
                        // the interpreter refuses an option with no program
                        None if argv.get(i).is_none() => return unknown(),
                        None if table.arg_not_dash && argv[i].starts_with('-') => return unknown(),
                        None => {
                            i += 1;
                            (i - 1, 0)
                        }
                    };
                    if !table.code_continues {
                        return Reading {
                            runs: Runs::Code,
                            code: Some(at),
                        };
                    }
                    // node: the options go on after the program
                    code.get_or_insert(at);
                    continue;
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
                None => return end(argv, i - 1, shell_code, stdin, code),
            },
        };
        words = false;
        // a `+` cluster (a shell's)
        let plus = a.starts_with('+');
        // the letters of this cluster that take the next arguments
        let mut next: Vec<char> = Vec::new();
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
                Opt::NoRunAlone => seen.no_run_alone = true,
                Opt::Inspect => seen.inspect = true,
                Opt::Next => next.push(c),
                // `+c`, `+s`: as `-c`, `-s` for bash, dash and ash; not
                // an option to rely on in the ksh family and zsh (mksh runs
                // `+c CODE`'s `CODE` as a script)
                Opt::ShellCode | Opt::Stdin if plus && !table.plus_code => return unknown(),
                Opt::Stdin => stdin = true,
                // the rest of the cluster is options too, then its operands
                Opt::ShellCode => shell_code = true,
                Opt::Code => {
                    let start = a.len() - rest.len();
                    let at = if rest.is_empty() {
                        // the interpreter refuses an option with no program
                        if argv.get(i).is_none() {
                            return unknown();
                        }
                        i += 1;
                        (i - 1, 0)
                    } else {
                        (i - 1, start)
                    };
                    if !table.code_continues {
                        return Reading {
                            runs: Runs::Code,
                            code: Some(at),
                        };
                    }
                    // perl, ruby: the switches go on after the program
                    code.get_or_insert(at);
                    break;
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
                        if table.arg_not_dash && v.starts_with('-') {
                            return unknown();
                        }
                        i += 1;
                        v.as_str()
                    } else {
                        rest
                    };
                    if table.word_values.contains(c)
                        && (value.is_empty() || value.starts_with('-') || value.contains('/'))
                    {
                        return unknown();
                    }
                    if opt == Opt::Module {
                        // a module's name, never a path (python refuses
                        // one: nothing runs)
                        if value.is_empty() || value.contains('/') {
                            return unknown();
                        }
                        return Runs::Script(value.into()).into();
                    }
                    if !table.names_ok(c, value) {
                        return unknown();
                    }
                    seen.loads |= opt == Opt::Loads
                        || table
                            .loading_values
                            .iter()
                            .any(|(o, v)| *o == c && v.iter().any(|p| value.starts_with(p)));
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
        if argv.len() < i + next.len() {
            return unknown();
        }
        for (k, c) in next.iter().enumerate() {
            if !table.names_ok(*c, &argv[i + k]) {
                return unknown();
            }
        }
        i += next.len();
    }
    end(argv, i, shell_code, stdin, code)
}

/// The end of the options, at `at`: perl's or ruby's `-e` program if one
/// was read (the rest is its arguments), else [`operand`].
fn end(
    argv: &[String],
    at: usize,
    shell_code: bool,
    stdin: bool,
    code: Option<(usize, usize)>,
) -> Reading {
    if code.is_some() {
        return Reading {
            runs: Runs::Code,
            code,
        };
    }
    operand(argv, at, shell_code, stdin)
}

/// Lot 313 (BUG-49's residue, the coordinator's decision of 11/11/2026):
/// one encryption tool's options, as its own parser reads them — which set
/// its mode (encrypt, or another), and which take a value (the review of
/// #549, F7: `ccrypt -K -d`, `openssl enc -k -d` and `age -o -d.age` read a
/// value as the decrypt option and lost the encryption).
struct CryptTable {
    /// Letters (clustered, `-er`) and long options that ask to encrypt.
    on_short: &'static str,
    on_long: &'static [&'static str],
    /// … and that ask for another mode (decrypt, print, re-key).
    off_short: &'static str,
    off_long: &'static [&'static str],
    /// Letters and long options that take a value (the rest of the cluster,
    /// else the next argument; `--name=value`).
    value_short: &'static str,
    value_long: &'static [&'static str],
    /// Its mode without any such option.
    default: bool,
    /// The last mode option wins (`ccrypt -d -e` encrypts); else any
    /// encryption option does (gpg: `-se` signs and encrypts).
    last_wins: bool,
    /// gpg: a long option by its start (`--sy`), two letters or more.
    abbreviated: bool,
    /// openssl: options are words with one hyphen (`-in`, `-k`), no
    /// clusters.
    words: bool,
}

/// How a tool's argv asks for encryption.
enum Crypt {
    /// Its options, read with its table.
    Table(&'static CryptTable),
    /// A command first (`7z a`, `rar a`): one of `commands` with a switch
    /// starting with one of `switches` anywhere (`-pSECRET`, `-hp`).
    Command {
        commands: &'static [&'static str],
        switches: &'static [&'static str],
    },
    /// openssl: its command — `enc` or a cipher's name, a public-key
    /// command (`smime`, `cms`, `pkeyutl`, `rsautl`) — then that command's
    /// options.
    OpenSsl,
    /// Always (`ccencrypt`).
    Always,
}

const GPG: CryptTable = CryptTable {
    on_short: "ce",
    on_long: &["symmetric", "encrypt", "encrypt-files"],
    off_short: "",
    off_long: &[],
    value_short: "oruRfzF",
    value_long: &[
        "output",
        "recipient",
        "hidden-recipient",
        "recipient-file",
        "hidden-recipient-file",
        "encrypt-to",
        "hidden-encrypt-to",
        "local-user",
        "default-key",
        "passphrase",
        "passphrase-file",
        "passphrase-fd",
        "homedir",
        "keyring",
        "secret-keyring",
        "trust-model",
        "cipher-algo",
        "compress-algo",
        "digest-algo",
        "s2k-cipher-algo",
        "s2k-digest-algo",
        "s2k-mode",
        "s2k-count",
        "set-filename",
        "comment",
        "status-fd",
        "status-file",
        "logger-fd",
        "logger-file",
        "pinentry-mode",
        "compress-level",
        "default-recipient",
        "trusted-key",
    ],
    default: false,
    last_wins: false,
    abbreviated: true,
    words: false,
};

const AGE: CryptTable = CryptTable {
    on_short: "e",
    on_long: &["encrypt"],
    off_short: "d",
    off_long: &["decrypt"],
    value_short: "oriRj",
    value_long: &[
        "output",
        "recipient",
        "identity",
        "recipients-file",
        "plugin",
    ],
    default: true,
    last_wins: true,
    abbreviated: false,
    words: false,
};

const CCRYPT: CryptTable = CryptTable {
    on_short: "e",
    on_long: &["encrypt"],
    off_short: "dcxu",
    off_long: &["decrypt", "cat", "keychange", "unixcrypt"],
    value_short: "KkHSEPQ",
    value_long: &[
        "key", "keyfile", "key2", "suffix", "envvar", "prompt", "prompt2",
    ],
    default: true,
    last_wins: true,
    abbreviated: false,
    words: false,
};

const MCRYPT: CryptTable = CryptTable {
    on_short: "",
    on_long: &[],
    off_short: "d",
    off_long: &["decrypt"],
    value_short: "kfamsohc",
    value_long: &[
        "key",
        "keyfile",
        "algorithm",
        "mode",
        "keysize",
        "keymode",
        "hash",
        "config",
        "algorithms-directory",
        "modes-directory",
    ],
    default: true,
    last_wins: true,
    abbreviated: false,
    words: false,
};

const ZIPCLOAK: CryptTable = CryptTable {
    on_short: "",
    on_long: &[],
    off_short: "d",
    off_long: &["decrypt"],
    value_short: "Ob",
    value_long: &["output-file", "temp-path"],
    default: true,
    last_wins: true,
    abbreviated: false,
    words: false,
};

const ZIP: CryptTable = CryptTable {
    on_short: "eP",
    on_long: &["encrypt", "password"],
    off_short: "",
    off_long: &[],
    value_short: "bntxiOZs",
    value_long: &["temp-path", "suffixes", "exclude", "include", "output-file"],
    default: false,
    last_wins: false,
    abbreviated: false,
    words: false,
};

const AESCRYPT: CryptTable = CryptTable {
    on_short: "e",
    on_long: &[],
    off_short: "d",
    off_long: &[],
    value_short: "pko",
    value_long: &[],
    default: false,
    last_wins: true,
    abbreviated: false,
    words: false,
};

/// `openssl enc` and a cipher command (`openssl aes-256-cbc`).
const OPENSSL_ENC: CryptTable = CryptTable {
    on_short: "",
    on_long: &["e"],
    off_short: "",
    off_long: &["d"],
    value_short: "",
    value_long: &[
        "in",
        "out",
        "pass",
        "k",
        "kfile",
        "K",
        "iv",
        "S",
        "md",
        "engine",
        "bufsize",
        "iter",
        "saltlen",
        "provider",
        "provider-path",
        "propquery",
        "rand",
        "writerand",
        "skeyopt",
        "skeymgmt",
    ],
    default: true,
    last_wins: true,
    abbreviated: false,
    words: true,
};

/// openssl's public-key commands (`smime`, `cms`, `pkeyutl`, `rsautl`).
const OPENSSL_PK: CryptTable = CryptTable {
    on_short: "",
    on_long: &["encrypt"],
    off_short: "",
    off_long: &["decrypt", "sign", "verify"],
    value_short: "",
    value_long: &[
        "in",
        "out",
        "inkey",
        "recip",
        "passin",
        "keyform",
        "certfile",
        "signer",
        "peerkey",
        "inform",
        "outform",
        "keyopt",
        "engine",
        "provider",
        "propquery",
    ],
    default: false,
    last_wins: true,
    abbreviated: false,
    words: true,
};

/// The encryption tools, by the name of their executed file (a version
/// suffix of digits and dots allowed: `gpg2`).
const CRYPT_TOOLS: &[(&str, Crypt)] = &[
    ("gpg", Crypt::Table(&GPG)),
    ("gpgtar", Crypt::Table(&GPG)),
    ("openssl", Crypt::OpenSsl),
    ("age", Crypt::Table(&AGE)),
    ("rage", Crypt::Table(&AGE)),
    (
        "7z",
        Crypt::Command {
            commands: &["a", "u"],
            switches: &["-p", "-mhe"],
        },
    ),
    (
        "7za",
        Crypt::Command {
            commands: &["a", "u"],
            switches: &["-p", "-mhe"],
        },
    ),
    (
        "7zr",
        Crypt::Command {
            commands: &["a", "u"],
            switches: &["-p", "-mhe"],
        },
    ),
    (
        "7zz",
        Crypt::Command {
            commands: &["a", "u"],
            switches: &["-p", "-mhe"],
        },
    ),
    (
        "rar",
        Crypt::Command {
            commands: &["a", "u", "m", "f"],
            switches: &["-p", "-hp"],
        },
    ),
    ("zip", Crypt::Table(&ZIP)),
    ("zipcloak", Crypt::Table(&ZIPCLOAK)),
    ("ccrypt", Crypt::Table(&CCRYPT)),
    ("ccencrypt", Crypt::Always),
    ("mcrypt", Crypt::Table(&MCRYPT)),
    ("aescrypt", Crypt::Table(&AESCRYPT)),
    (
        "scrypt",
        Crypt::Command {
            commands: &["enc"],
            switches: &[""],
        },
    ),
];

/// The ciphers openssl runs as commands of their own (`openssl aes-256-cbc`),
/// by the start of their names.
const OPENSSL_CIPHERS: &[&str] = &[
    "aes", "aria", "bf", "blowfish", "camellia", "cast", "chacha", "des", "idea", "rc2", "rc4",
    "rc5", "seed", "sm4",
];

/// `args` (the tool's arguments, its name dropped) read with `table`: the
/// mode the tool runs in — `true`: it encrypts.
fn crypt_mode(table: &CryptTable, args: &[&str]) -> bool {
    let mut mode: Option<bool> = None;
    let mut set = |on: bool| {
        if table.last_wins || mode != Some(true) {
            mode = Some(on);
        }
    };
    let mut i = 0;
    while let Some(a) = args.get(i) {
        i += 1;
        if *a == "--" {
            break;
        }
        let long = if table.words {
            a.strip_prefix("--").or_else(|| a.strip_prefix('-'))
        } else {
            a.strip_prefix("--")
        };
        if let Some(name) = long.filter(|n| !n.is_empty()) {
            let (name, value) = match name.split_once('=') {
                Some((n, _)) => (n, true),
                None => (name, false),
            };
            let abbreviates = |list: &[&str]| {
                list.contains(&name)
                    || (table.abbreviated
                        && name.len() >= 2
                        && list.iter().any(|l| l.starts_with(name)))
            };
            if table.value_long.contains(&name) {
                if !value {
                    i += 1;
                }
            } else if abbreviates(table.on_long) {
                set(true);
            } else if table.off_long.contains(&name) {
                set(false);
            }
            continue;
        }
        let Some(letters) = a.strip_prefix('-').filter(|l| !l.is_empty()) else {
            continue;
        };
        for (at, c) in letters.char_indices() {
            if table.value_short.contains(c) {
                // the rest of the cluster, else the next argument
                if at + c.len_utf8() == letters.len() {
                    i += 1;
                }
                break;
            }
            if table.on_short.contains(c) {
                set(true);
            } else if table.off_short.contains(c) {
                set(false);
            }
        }
    }
    mode.unwrap_or(table.default)
}

/// Lot 313 (BUG-49's residue): `exe` is an encryption tool (`openssl enc`,
/// `gpg -c`/`--symmetric`/`-e`, `age`, `7z a -p`, `zip -e`/`-P`, `rar a -p`,
/// `ccrypt`, `mcrypt`, `aescrypt -e`, `scrypt enc`) and `argv` asks it to
/// encrypt, read with the tool's own option table ([`CryptTable`]: a value
/// is never read as an option; the last mode wins where the tool's does).
/// What the ransomware signal does not trust it for: its ciphertext-like
/// content (b) and renames to a new extension (c), whoever started it; its
/// outputs count as ciphertext whatever their header.
pub fn encrypts(exe: &Path, argv: &[String]) -> bool {
    let Some(base) = exe.file_name().map(|n| n.to_string_lossy()) else {
        return false;
    };
    let Some((_, crypt)) = CRYPT_TOOLS.iter().find(|(name, _)| {
        base.strip_prefix(name)
            .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit() || c == '.'))
    }) else {
        return false;
    };
    let args: Vec<&str> = argv.iter().skip(1).map(String::as_str).collect();
    match crypt {
        Crypt::Table(table) => crypt_mode(table, &args),
        Crypt::Command { commands, switches } => {
            let args: Vec<&str> = args.iter().copied().take_while(|a| *a != "--").collect();
            args.iter()
                .find(|a| !a.starts_with('-'))
                .is_some_and(|c| commands.contains(&c.to_ascii_lowercase().as_str()))
                && args.iter().any(|a| {
                    switches
                        .iter()
                        .any(|s| a.to_ascii_lowercase().starts_with(s))
                })
        }
        Crypt::OpenSsl => {
            let Some(command) = args.first() else {
                return false;
            };
            if *command == "enc" || OPENSSL_CIPHERS.iter().any(|c| command.starts_with(c)) {
                crypt_mode(&OPENSSL_ENC, &args[1..])
            } else if ["smime", "cms", "pkeyutl", "rsautl"].contains(command) {
                crypt_mode(&OPENSSL_PK, &args[1..])
            } else {
                false
            }
        }
        Crypt::Always => true,
    }
}

/// The first argument that is not an option, at `at`: the script; after a
/// shell's `-c`, its program ([`Runs::Code`]; none: the shell refuses,
/// [`Runs::Unknown`]); after `-s`, the standard input's ([`Runs::Code`]);
/// none, [`Runs::Inline`].
fn operand(argv: &[String], at: usize, shell_code: bool, stdin: bool) -> Reading {
    match argv.get(at) {
        Some(_) if shell_code => Reading {
            runs: Runs::Code,
            code: Some((at, 0)),
        },
        None if shell_code => Runs::Unknown(None).into(),
        _ if stdin => Runs::Code.into(),
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
    /// `bash -ovi` is `-o` then `-v -i`, as bash reads it. Lot 310, the
    /// review of #539: the name `-o` takes is checked — `bash -ovi /tmp/s`
    /// takes `/tmp/s` for an option's name, refuses it and runs nothing
    /// (`invalid option name`, status 2), so it reads as unknown, not as an
    /// interactive shell; `bash -ovi vi` is the interactive one.
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
            runs_of(Path::new("/usr/bin/bash"), &argv(&["bash", "-ovi", "vi"])),
            Runs::Inline
        );
        assert_eq!(
            runs_of(
                Path::new("/usr/bin/bash"),
                &argv(&["bash", "-ovi", "/tmp/s"])
            ),
            Runs::Unknown(Some("/tmp/s".into()))
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

    /// Lot 313 (BUG-49's residue): an encryption tool's argv in its
    /// encryption mode, as each tool reads it; its other modes are not.
    #[test]
    fn an_encryption_tool_s_encryption_argv() {
        let e = |exe: &str, a: &[&str]| encrypts(Path::new(exe), &argv(a));
        for (exe, a) in [
            (
                "/usr/bin/openssl",
                &[
                    "openssl",
                    "enc",
                    "-aes-256-cbc",
                    "-in",
                    "a",
                    "-out",
                    "a.enc",
                ][..],
            ),
            (
                "/usr/bin/openssl",
                &["openssl", "aes-256-cbc", "-salt", "-k", "x"],
            ),
            ("/usr/bin/openssl", &["openssl", "chacha20", "-in", "a"]),
            (
                "/usr/bin/openssl",
                &["openssl", "smime", "-encrypt", "-in", "a", "cert.pem"],
            ),
            (
                "/usr/bin/openssl",
                &["openssl", "pkeyutl", "-encrypt", "-pubin"],
            ),
            ("/usr/bin/gpg", &["gpg", "-c", "a"]),
            (
                "/usr/bin/gpg",
                &["gpg", "--batch", "--passphrase", "x", "--symmetric", "a"],
            ),
            ("/usr/bin/gpg", &["gpg", "--symm", "a"]),
            ("/usr/bin/gpg", &["gpg", "-sear", "bob", "a"]),
            ("/usr/bin/gpg", &["gpg", "--encrypt", "-r", "bob", "a"]),
            (
                "/usr/bin/gpg",
                &["gpg", "--encrypt-files", "-r", "bob", "a", "b"],
            ),
            ("/usr/bin/gpg2", &["gpg2", "-e", "-r", "bob", "a"]),
            (
                "/usr/bin/gpgtar",
                &["gpgtar", "--symmetric", "-o", "x.gpg", "dir"],
            ),
            ("/usr/bin/age", &["age", "-p", "-o", "a.age", "a"]),
            ("/usr/bin/age", &["age", "-r", "age1xyz", "a"]),
            (
                "/usr/bin/7z",
                &["7z", "a", "-pSECRET", "-mhe=on", "x.7z", "dir"],
            ),
            ("/usr/bin/7za", &["7za", "a", "x.7z", "dir", "-p"]),
            ("/usr/bin/zip", &["zip", "-e", "-r", "x.zip", "dir"]),
            ("/usr/bin/zip", &["zip", "-rP", "secret", "x.zip", "dir"]),
            ("/usr/bin/zip", &["zip", "--password", "s", "x.zip", "a"]),
            ("/usr/bin/zipcloak", &["zipcloak", "x.zip"]),
            ("/usr/bin/rar", &["rar", "a", "-hpSECRET", "x.rar", "dir"]),
            ("/usr/bin/ccrypt", &["ccrypt", "-K", "k", "a"]),
            ("/usr/bin/ccencrypt", &["ccencrypt", "a"]),
            ("/usr/bin/mcrypt", &["mcrypt", "a"]),
            ("/usr/bin/aescrypt", &["aescrypt", "-e", "-p", "x", "a"]),
            ("/usr/bin/scrypt", &["scrypt", "enc", "a", "a.enc"]),
            // the review of #549 (F7): a value read as an option, and the
            // last mode, read as each tool reads them
            (
                "/usr/bin/ccrypt",
                &["ccrypt", "-e", "-K", "-d", "-r", "/srv"],
            ),
            ("/usr/bin/ccrypt", &["ccrypt", "-d", "-e", "-r", "/srv"]),
            ("/usr/bin/ccrypt", &["ccrypt", "-S", "-dx", "-r", "/srv"]),
            (
                "/usr/bin/openssl",
                &[
                    "openssl",
                    "enc",
                    "-aes-256-cbc",
                    "-k",
                    "-d",
                    "-in",
                    "a",
                    "-out",
                    "a.e",
                ],
            ),
            (
                "/usr/bin/openssl",
                &["openssl", "enc", "-d", "-e", "-aes-256-cbc", "-in", "a"],
            ),
            ("/usr/bin/age", &["age", "-p", "-o", "-d.age", "a"]),
            ("/usr/bin/mcrypt", &["mcrypt", "-k", "-d", "a"]),
            ("/usr/bin/gpg", &["gpg", "--sy", "a"]),
        ] {
            assert!(e(exe, a), "{a:?}");
        }
        for (exe, a) in [
            (
                "/usr/bin/openssl",
                &["openssl", "enc", "-d", "-aes-256-cbc", "-in", "a.enc"][..],
            ),
            (
                "/usr/bin/openssl",
                &["openssl", "x509", "-in", "c.pem", "-noout"],
            ),
            (
                "/usr/bin/openssl",
                &["openssl", "s_client", "-connect", "h:443"],
            ),
            ("/usr/bin/openssl", &["openssl", "dgst", "-sha256", "a"]),
            ("/usr/bin/openssl", &["openssl", "base64", "-in", "a"]),
            ("/usr/bin/openssl", &["openssl"]),
            ("/usr/bin/gpg", &["gpg", "--verify", "a.sig", "a"]),
            ("/usr/bin/gpg", &["gpg", "--decrypt", "a.gpg"]),
            ("/usr/bin/gpg", &["gpg", "-d", "a.gpg"]),
            ("/usr/bin/gpg", &["gpg", "--list-keys"]),
            (
                "/usr/bin/gpg",
                &["gpg", "--encrypt-to", "bob", "--sign", "a"],
            ),
            // after `--`, a file's name, whatever it looks like
            ("/usr/bin/gpg", &["gpg", "--decrypt", "--", "-ce.gpg"]),
            ("/usr/bin/age", &["age", "-d", "-i", "key", "a.age"]),
            ("/usr/bin/age", &["age", "--decrypt", "a.age"]),
            ("/usr/bin/7z", &["7z", "x", "-pSECRET", "x.7z"]),
            ("/usr/bin/7z", &["7z", "a", "x.7z", "dir"]),
            ("/usr/bin/zip", &["zip", "-r", "x.zip", "dir"]),
            ("/usr/bin/zipcloak", &["zipcloak", "-d", "x.zip"]),
            ("/usr/bin/ccrypt", &["ccrypt", "-d", "a.cpt"]),
            ("/usr/bin/ccrypt", &["ccrypt", "--cat", "a.cpt"]),
            ("/usr/bin/ccrypt", &["ccrypt", "-e", "-d", "a.cpt"]),
            ("/usr/bin/ccrypt", &["ccrypt", "-K", "k", "-d", "a.cpt"]),
            (
                "/usr/bin/openssl",
                &["openssl", "enc", "-e", "-d", "-in", "a.enc"],
            ),
            (
                "/usr/bin/openssl",
                &["openssl", "enc", "-pass", "pass:x", "-d", "-in", "a"],
            ),
            ("/usr/bin/age", &["age", "-o", "x", "--decrypt", "a.age"]),
            ("/usr/bin/aescrypt", &["aescrypt", "-d", "-p", "x", "a.aes"]),
            ("/usr/bin/scrypt", &["scrypt", "dec", "a.enc", "a"]),
            ("/usr/bin/tar", &["tar", "-czf", "x.tgz", "dir"]),
            ("/usr/bin/agetty", &["agetty", "tty1"]),
        ] {
            assert!(!e(exe, a), "{a:?}");
        }
    }

    /// Lot 313: busybox reads its program as busybox does — a name starting
    /// with `busybox` is busybox itself, again and again, and `--help`,
    /// `--list` and `--install` run none.
    #[test]
    fn busybox_reads_its_program_as_busybox_does() {
        let p = |a: &[&str]| busybox_program(&argv(a)).map(|(n, at)| (n.to_string(), at));
        assert_eq!(p(&["-sh"]), Some(("sh".into(), 1)));
        assert_eq!(p(&["/bin/ash", "-i"]), Some(("ash".into(), 1)));
        assert_eq!(p(&["busybox", "sh"]), Some(("sh".into(), 2)));
        assert_eq!(p(&["busybox.static", "/bin/sh"]), Some(("sh".into(), 2)));
        assert_eq!(p(&["busybox", "busybox", "hush"]), Some(("hush".into(), 3)));
        assert_eq!(p(&["busybox", "-sh"]), Some(("-sh".into(), 2)));
        for a in [
            &["busybox"][..],
            &["busybox", "--help", "sh"],
            &["busybox", "--list"],
            &["busybox", "--list-full"],
            &["busybox", "--install", "-s"],
            &[],
        ] {
            assert_eq!(p(a), None, "{a:?}");
        }
        // the interpreters' reader agrees
        use crate::posture::lineage::ExecIdentity;
        for a in [
            &["busybox.static", "sh", "/tmp/steal.sh"][..],
            &["busybox", "busybox", "sh", "/tmp/steal.sh"],
        ] {
            assert_eq!(
                ExecIdentity::of_exec("/bin/busybox", &argv(a)).runs,
                Runs::Script("/tmp/steal.sh".into()),
                "{a:?}"
            );
        }
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

    /// The review of #539's differential test, with a program on standard
    /// input and a strict oracle (`agent/tests/interpreter_differential.rs`):
    /// an option the interpreter refuses for want of its program, or whose
    /// value it refuses, runs nothing (not known, never `Code`); `-` is the
    /// standard input's program, not a script named `-`; a shell's `-s`
    /// reads its cluster to the end (dash's `-posix S1` refuses `S1` as
    /// `-o`'s name); perl's and ruby's switches go on after `-e CODE`.
    #[test]
    fn review_the_strict_differential_s_findings() {
        let (perl, py, bash, dash, ruby) = (
            Path::new("/usr/bin/perl"),
            Path::new("/usr/bin/python3"),
            Path::new("/usr/bin/bash"),
            Path::new("/usr/bin/dash"),
            Path::new("/usr/bin/ruby"),
        );
        let unknown = |exe: &Path, a: &[&str]| {
            let r = runs_of(exe, &argv(a));
            assert!(matches!(r, Runs::Unknown(_)), "{exe:?} {a:?}: {r:?}");
        };
        // no program for the option: refused
        unknown(perl, &["perl", "-e"]);
        unknown(perl, &["perl", "-T", "-C -e"]);
        unknown(perl, &["perl", "-E", "CODE", "-s", "-E"]);
        unknown(py, &["python3", "-c"]);
        unknown(py, &["python3", "-Ic"]);
        unknown(bash, &["bash", "-c"]);
        unknown(bash, &["bash", "-ec", "-p"]);
        unknown(Path::new("/usr/bin/node"), &["node", "-e"]);
        unknown(Path::new("/usr/bin/node"), &["node", "--eval"]);
        // a value refused
        unknown(py, &["python3", "--check-hash-based-pycs", "-O", "/tmp/s"]);
        unknown(py, &["python3", "-m", "/tmp/s"]);
        unknown(dash, &["sh", "-posix", "/tmp/s"]);
        unknown(dash, &["sh", "-s", "-C", "-l", "-P"]);
        unknown(bash, &["bash", "-f", "-restricted", "-I"]);
        // perl -u dumps core: the program does not run
        unknown(perl, &["perl", "-u", "/tmp/s"]);
        // the switches after `-e CODE`
        unknown(perl, &["perl", "-lane", "CODE", "-n", "-c"]);
        assert_eq!(
            runs_of(
                py,
                &argv(&["python3", "--check-hash-based-pycs", "always", "/tmp/s"])
            ),
            Runs::Script("/tmp/s".into())
        );
        for (exe, a) in [
            (perl, &["perl", "-"][..]),
            (perl, &["perl", "-w", "-", "/tmp/s"]),
            (py, &["python3", "-"]),
            (py, &["python3", "-O", "-", "/tmp/s"]),
            (py, &["python3", "-Wignore", "--", "-", "-O"]),
            (bash, &["bash", "-s", "/tmp/s", "x"]),
            (dash, &["sh", "-s"]),
        ] {
            assert_eq!(runs_of(exe, &argv(a)), Runs::Code, "{a:?}");
        }
        // the guest's run (node 18, ruby 3.2, busybox 1.36, mksh R59c):
        // node refuses a value starting with `-` and reads options after
        // its program; ruby's `-E` takes an encoding, `-C` moves the
        // script's directory, `-s` lets the script's arguments set its
        // globals; busybox's ash has no `-p`, no `-V`; mksh's `+c` runs no
        // command string
        let (node, bb, mksh) = (
            Path::new("/usr/bin/node"),
            Path::new("/bin/busybox"),
            Path::new("/usr/bin/mksh"),
        );
        unknown(node, &["node", "--title", "--trace-warnings", "/tmp/s"]);
        unknown(node, &["node", "-r", "-x", "/tmp/s"]);
        // the re-check (N4): a test reporter and a bytecode cache are code
        // loaded beside the program named
        unknown(
            node,
            &[
                "node",
                "--test",
                "--test-reporter=/tmp/r.mjs",
                "/usr/bin/aws",
            ],
        );
        unknown(
            node,
            &[
                "node",
                "--test",
                "--test-reporter",
                "/tmp/r.mjs",
                "/usr/bin/aws",
            ],
        );
        unknown(
            py,
            &["python3", "-X", "pycache_prefix=/tmp/c", "/usr/bin/aws"],
        );
        unknown(py, &["python3", "-Xpresite=m", "/usr/bin/aws"]);
        assert_eq!(
            runs_of(py, &argv(&["python3", "-X", "dev", "/usr/bin/aws"])),
            Runs::Script("/usr/bin/aws".into())
        );
        unknown(node, &["node", "-C", "-x", "/tmp/s"]);
        unknown(node, &["node", "-p", "A", "--version"]);
        unknown(node, &["node", "--print", "A", "--require"]);
        unknown(ruby, &["ruby", "-E", "-W", "/tmp/s"]);
        unknown(ruby, &["ruby", "-E", "/tmp/x", "/tmp/s"]);
        unknown(ruby, &["ruby", "-C", "/tmp", "/tmp/s"]);
        unknown(ruby, &["ruby", "-s", "/tmp/s", "-0"]);
        unknown(bb, &["sh", "-p", "/tmp/s"]);
        unknown(bb, &["sh", "-V", "/tmp/s"]);
        unknown(mksh, &["mksh", "+c", "CODE"]);
        assert_eq!(
            runs_of(node, &argv(&["node", "--title", "t", "/tmp/s"])),
            Runs::Script("/tmp/s".into())
        );
        assert_eq!(
            runs_of(ruby, &argv(&["ruby", "-E", "UTF-8", "/tmp/s"])),
            Runs::Script("/tmp/s".into())
        );
        for (exe, a) in [
            (bash, &["bash", "+c", "CODE"][..]),
            (dash, &["sh", "+c", "CODE"]),
            (bb, &["sh", "+c", "CODE"]),
        ] {
            assert_eq!(runs_of(exe, &argv(a)), Runs::Code, "{a:?}");
        }
        for (exe, a, prog) in [
            (
                node,
                &["node", "-e", "A", "--no-warnings", "/tmp/s"][..],
                "A",
            ),
            (node, &["node", "--eval", "A", "--no-warnings"], "A"),
            (perl, &["perl", "-e", "A", "-e", "B", "/tmp/s"][..], "A"),
            (perl, &["perl", "-e", "A", "-n", "/tmp/s"], "A"),
            (perl, &["perl", "-e", "A", "-"], "A"),
            (ruby, &["ruby", "-e", "A", "-w", "/tmp/s"], "A"),
        ] {
            let a = argv(a);
            assert_eq!(runs_of(exe, &a), Runs::Code, "{a:?}");
            assert_eq!(inline_program(exe, &a), Some(prog), "{a:?}");
        }
    }

    /// The re-check of #539 (N5): `NODE_OPTIONS` loads code only with a
    /// loading option of node's table; memory and diagnostics options do
    /// not.
    #[test]
    fn node_options_load_only_with_a_loading_option() {
        for v in [
            "--require /tmp/x.js",
            "--max-old-space-size=64 --import=data:text/javascript,x",
            "-r/tmp/x.js",
            "-r /tmp/x.js",
            "--test-reporter=/tmp/r.mjs",
            "\"--experimental-loader\" /tmp/l.mjs",
        ] {
            assert!(node_options_load(v), "{v}");
        }
        for v in [
            "--max-old-space-size=4096",
            "--max-old-space-size 4096 --enable-source-maps",
            "--no-warnings --trace-warnings",
            "--stack-size=500",
            "",
        ] {
            assert!(!node_options_load(v), "{v}");
        }
    }

    /// The review of #539's differential test: `python3 -i S` runs `S`,
    /// then its standard input (`python3 -i /usr/bin/x < code`: the
    /// caller's code under an installed script's name) — not known; `-i`
    /// with an inline program or nothing named reads as without it.
    #[test]
    fn review_python_inspect_runs_its_standard_input_after_the_script() {
        let py = Path::new("/usr/bin/python3");
        for a in [
            &["python3", "-i", "/usr/bin/x"][..],
            &["python3", "-iO", "/usr/bin/x"],
            &["python3", "-Oi", "/usr/bin/x"],
            &["python3", "-i", "-m", "json.tool"],
        ] {
            assert!(
                matches!(runs_of(py, &argv(a)), Runs::Unknown(Some(_))),
                "{a:?}: {:?}",
                runs_of(py, &argv(a))
            );
        }
        assert_eq!(runs_of(py, &argv(&["python3", "-i"])), Runs::Inline);
        assert_eq!(
            runs_of(py, &argv(&["python3", "-i", "-c", "x"])),
            Runs::Code
        );
        assert_eq!(
            runs_of(py, &argv(&["python3", "-I", "/usr/bin/x"])),
            Runs::Script("/usr/bin/x".into()),
            "-I (isolated) is no -i"
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
        // ruby's -v prints the version and runs the script given; with
        // none, nothing (it reads no standard input)
        assert_eq!(
            runs_of(Path::new("/usr/bin/ruby"), &argv(&["ruby", "-v", "/tmp/s"])),
            Runs::Script("/tmp/s".into())
        );
        assert_eq!(
            runs_of(Path::new("/usr/bin/ruby"), &argv(&["ruby", "-v"])),
            Runs::Unknown(None)
        );
        assert_eq!(
            runs_of(Path::new("/usr/bin/ruby"), &argv(&["ruby", "-wv"])),
            Runs::Unknown(None)
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

    /// Lot 313 (the review of #549, F4): the dynamic loader runs the
    /// program its first operand names, read past the loader's options
    /// with their arities — what the process is; `--preload` and `--audit`
    /// load the caller's code into it; `--help` runs nothing.
    #[test]
    fn the_dynamic_loader_runs_its_operand() {
        use crate::posture::lineage::ExecIdentity;
        let ld = "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2";
        for (a, want) in [
            (
                &["ld.so", "/usr/bin/aws", "s3", "ls"][..],
                Runs::Script("/usr/bin/aws".into()),
            ),
            (
                &[
                    "ld.so",
                    "--library-path",
                    "/tmp",
                    "--argv0",
                    "aws",
                    "/usr/bin/aws",
                ],
                Runs::Script("/usr/bin/aws".into()),
            ),
            (
                &[
                    "ld.so",
                    "--library-path=/tmp",
                    "--inhibit-cache",
                    "/bin/bash",
                    "-i",
                ],
                Runs::Script("/bin/bash".into()),
            ),
            (&["ld.so", "--", "/bin/sh"], Runs::Script("/bin/sh".into())),
        ] {
            assert_eq!(ExecIdentity::of_exec(ld, &argv(a)).runs, want, "{a:?}");
        }
        assert_eq!(
            loader_program(&argv(&["ld.so", "--argv0", "x", "/bin/bash", "-i"])),
            Some(("/bin/bash", 3))
        );
        for a in [
            &["ld.so"][..],
            &["ld.so", "--help"],
            &["ld.so", "--frobnicate", "/bin/sh"],
            &["ld.so", "--library-path"],
        ] {
            assert_eq!(loader_program(&argv(a)), None, "{a:?}");
        }
        // the program it runs is what a client is: the aws client through
        // the loader is aws; a script it runs from /tmp is no installed one
        let id = ExecIdentity::of_exec(ld, &argv(&["ld.so", "/tmp/x"]));
        assert!(!id.is_installed_program());
        for name in [
            "ld-linux-x86-64.so.2",
            "ld-linux-aarch64.so.1",
            "ld-linux.so.2",
            "ld64.so.2",
            "ld-musl-x86_64.so.1",
            "ld.so",
        ] {
            assert!(is_loader_name(name), "{name}");
        }
        for name in ["ld", "ldd", "ldconfig", "ld-linux", "ld.gold"] {
            assert!(!is_loader_name(name), "{name}");
        }
    }
}
