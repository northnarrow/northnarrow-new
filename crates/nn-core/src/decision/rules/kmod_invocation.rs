//! Lot 279: what an exec of a kernel-module tool asks for, judged on its
//! command line's SYNTAX alone (kmod 29..=34: `tools/kmod.c`,
//! `tools/modprobe.c`, `tools/insmod.c`). No I/O and no resolution: R011
//! does not emulate kmod's lookup (`modprobe.d`, the indexes, the files'
//! owners and times — the coordinator's decision of 04/11, after the
//! independent review of #498 found that emulation incomplete in ways that
//! read loads as "nothing to load"). What the tool's environment and
//! program are is the exec pump's to read ([`super::kmod_exec_facts`]).
//!
//! - **kmod is a multi-call binary**: `insmod`, `modprobe`, `lsmod`, `rmmod`,
//!   `modinfo` and `depmod` are links to `/usr/bin/kmod`, which runs as the
//!   basename of `argv[0]` (`program_invocation_short_name`), not as the name
//!   of the file executed: `execve("/usr/bin/kmod", ["insmod", …])` is an
//!   insmod whose `comm` is `kmod`. As `kmod` it runs the subcommand
//!   `argv[1]` (`help`, `list`, `static-nodes`; `insert`/`remove` in an
//!   experimental build).
//! - **Killed, on the command line alone** (as R011 killed every exec
//!   before lot 279):
//!   - `insmod`, whatever its arguments: it loads the FILE it is given;
//!   - a `modprobe` argument holding a `/`, or ending in `.ko`, `.ko.xz`,
//!     `.ko.zst` or `.ko.gz`: a file, not a module of the system's tree;
//!   - the options that take the module tree, the configuration or the
//!     kernel version from the caller (`-d`/`--dirname`, `-C`/`--config`,
//!     `-S`/`--set-version`), that force the load past the kernel's checks
//!     (`-f`, `--force`, `--force-modversion`, `--force-vermagic`), `-o`
//!     (module-init-tools' rename of the module; kmod refuses it), and
//!     `--remove-holders` / `--remove-dependencies`, which kmod 29..=34 run
//!     as an INSERTION (they do not set the removal: the review of #498,
//!     B-1) — each also by any abbreviation `getopt_long` accepts;
//!   - an option the tool itself refuses (unknown, ambiguous, its argument
//!     missing), as before;
//!   - ANY argument starting with `-` after the first module name.
//!     `getopt_long` permutes, but `POSIXLY_CORRECT` in the environment
//!     stops it and `MODPROBE_OPTIONS='--'` ends the options: whether such
//!     an argument is an option or a module parameter is the environment's
//!     to say (the review's B-4), so it is not read either way;
//!   - a module name starting with `-` (after `--`);
//!   - a `kmod` command other than those that load nothing.
//! - **Recorded**: `modprobe` of plain module names with, before the first
//!   name, only options that neither move nor force anything (`-a`, `-r`,
//!   `-n`, `-q`, `-v`, `-s`, `-i`, `-b`, `-w`, `-R`, `-D`, `-c`,
//!   `--first-time`, `--show-*`, `-V`, `-h`, `--`); `kmod help`, `list`,
//!   `static-nodes` and the version; kmod run as `lsmod`, `rmmod`, `modinfo`
//!   or `depmod` (they insert nothing). Whether the names load anything,
//!   and what, is the kernel's to judge at the load (R018 records it; the
//!   module signature policy refuses what it does not trust).

/// The tool an exec runs as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    Modprobe,
    Insmod,
    /// `kmod <command>`.
    Kmod,
    /// A kmod mode that loads nothing (`lsmod`, `rmmod`, `modinfo`,
    /// `depmod`).
    Other(&'static str),
}

/// What R011 makes of an invocation's command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Syntax {
    /// Module names only, nothing moved or forced, or a command that
    /// inserts nothing: recorded (what it asks for).
    Record(String),
    /// Killed (why).
    Kill(String),
}

/// The kmod modes `argv[0]` selects (`kmod_compat_cmds`).
const COMPAT: &[&str] = &["insmod", "modprobe", "lsmod", "rmmod", "modinfo", "depmod"];

/// The directories the distribution installs the module tools in.
const TOOL_DIRS: &[&str] = &["/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/"];

/// The basename of `path`.
fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// The tool an exec of `image` (the file the kernel executed, or the path
/// the caller passed when the kernel's is unknown) with `argv` runs as —
/// `Err` when it is not the distribution's module tool, or its mode is not
/// certain.
///
/// The tool must be a file of the system's binary directories named `kmod`,
/// `modprobe` or `insmod` (a copy elsewhere is the payload, a program of
/// another name is no module tool; that it is the system's FILE is the exec
/// pump's check, [`super::kmod_exec_facts`]). For `kmod` the mode is
/// `argv[0]`'s basename. A `modprobe` or `insmod` file is a link to kmod on
/// every distribution this runs on — a hard link shows its own name, not
/// kmod's — or a tool of that one name: `argv[0]` must name it too, so both
/// readings agree.
pub fn tool_of(image: &str, argv: &[String]) -> Result<Tool, String> {
    let in_tool_dir = TOOL_DIRS.iter().any(|d| {
        image
            .strip_prefix(d)
            .is_some_and(|rest| !rest.is_empty() && !rest.contains('/'))
    });
    if !in_tool_dir {
        return Err(format!(
            "{image} is not the system's module tool (it lives outside /usr/bin, /usr/sbin, \
             /bin and /sbin)"
        ));
    }
    // the exact name: a deleted image (`kmod (deleted)`) is none of them
    let file = basename(image);
    if !matches!(file, "kmod" | "modprobe" | "insmod") {
        return Err(format!("{image} is not the system's module tool"));
    }
    let Some(arg0) = argv.first() else {
        return Err("its argv was not read".to_string());
    };
    let mode = basename(arg0);
    if file != "kmod" && mode != file {
        return Err(format!(
            "argv[0] '{arg0}' would run {image} as another tool than {file} if it is kmod"
        ));
    }
    Ok(match mode {
        "modprobe" => Tool::Modprobe,
        "insmod" => Tool::Insmod,
        "kmod" => Tool::Kmod,
        m => match COMPAT.iter().find(|c| **c == m) {
            Some(c) => Tool::Other(c),
            None => {
                return Err(format!(
                    "argv[0] '{arg0}' names no mode of kmod (it exits with an error)"
                ))
            }
        },
    })
}

/// What R011 makes of `tool` run with `argv` (`argv[0]` first).
pub fn judge(tool: Tool, argv: &[String]) -> Syntax {
    let args = argv.get(1..).unwrap_or_default();
    match tool {
        Tool::Modprobe => modprobe(args),
        Tool::Insmod => Syntax::Kill(match args.iter().find(|a| !a.starts_with('-')) {
            Some(file) => {
                format!("insmod loads the file '{file}' as given, which no module tree resolves")
            }
            None => "insmod loads the file it is given, which no module tree resolves".to_string(),
        }),
        Tool::Kmod => kmod(args),
        Tool::Other(mode) => Syntax::Record(format!("kmod run as {mode}, which inserts nothing")),
    }
}

/// What one of modprobe's options is to R011.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Opt {
    /// Every operand is a module name (`-a`).
    All,
    /// Moves nothing and forces nothing.
    Plain,
    /// Killed (why).
    Kill(&'static str),
}

const CONFIG: &str = "told to take its configuration from the caller (-C/--config)";
const DIRNAME: &str = "told to take the module tree's root from the caller (-d/--dirname)";
const SET_VERSION: &str = "told to take the kernel version from the caller (-S/--set-version)";
const FORCE: &str = "told to force the load past the kernel's version checks (-f/--force*)";
const RENAME: &str = "told to rename the module (-o, module-init-tools'; kmod refuses it)";
const HOLDERS: &str = "given --remove-holders/--remove-dependencies, which kmod 29..34 run as \
                       an insertion (they do not set the removal)";

/// modprobe's long options (kmod 29..=34), with whether each takes an
/// argument.
const MODPROBE_LONG: &[(&str, bool, Opt)] = &[
    ("all", false, Opt::All),
    ("remove", false, Opt::Plain),
    ("remove-dependencies", false, Opt::Kill(HOLDERS)),
    ("remove-holders", false, Opt::Kill(HOLDERS)),
    ("wait", true, Opt::Plain),
    ("resolve-alias", false, Opt::Plain),
    ("first-time", false, Opt::Plain),
    ("ignore-install", false, Opt::Plain),
    ("ignore-remove", false, Opt::Plain),
    ("use-blacklist", false, Opt::Plain),
    ("force", false, Opt::Kill(FORCE)),
    ("force-modversion", false, Opt::Kill(FORCE)),
    ("force-vermagic", false, Opt::Kill(FORCE)),
    ("show-depends", false, Opt::Plain),
    ("showconfig", false, Opt::Plain),
    ("show-config", false, Opt::Plain),
    ("show-modversions", false, Opt::Plain),
    ("dump-modversions", false, Opt::Plain),
    ("show-exports", false, Opt::Plain),
    ("dry-run", false, Opt::Plain),
    ("show", false, Opt::Plain),
    ("config", true, Opt::Kill(CONFIG)),
    ("dirname", true, Opt::Kill(DIRNAME)),
    ("set-version", true, Opt::Kill(SET_VERSION)),
    ("syslog", false, Opt::Plain),
    ("quiet", false, Opt::Plain),
    ("verbose", false, Opt::Plain),
    ("version", false, Opt::Plain),
    ("help", false, Opt::Plain),
];

/// modprobe's short option `c`: whether it takes an argument, what it is.
fn modprobe_short(c: char) -> Option<(bool, Opt)> {
    Some(match c {
        'a' => (false, Opt::All),
        'w' => (true, Opt::Plain),
        'r' | 'R' | 'i' | 'b' | 's' | 'q' | 'v' | 'D' | 'c' | 'n' | 'V' | 'h' => {
            (false, Opt::Plain)
        }
        'f' => (false, Opt::Kill(FORCE)),
        'C' => (true, Opt::Kill(CONFIG)),
        'd' => (true, Opt::Kill(DIRNAME)),
        'S' => (true, Opt::Kill(SET_VERSION)),
        'o' => (true, Opt::Kill(RENAME)),
        _ => return None,
    })
}

/// A long option as `getopt_long` matches it: the exact name, else the
/// option every name the prefix starts is (several names of one meaning
/// are one; names of different meanings are ambiguous, which the tool
/// refuses).
fn long_option(name: &str) -> Result<(bool, Opt), String> {
    if let Some((_, arg, o)) = MODPROBE_LONG.iter().find(|(n, _, _)| *n == name) {
        return Ok((*arg, *o));
    }
    let mut found: Option<(bool, Opt)> = None;
    for (n, arg, o) in MODPROBE_LONG {
        if n.starts_with(name) {
            match found {
                Some(f) if f != (*arg, *o) => {
                    return Err(format!("--{name} is ambiguous (the tool refuses it)"));
                }
                _ => found = Some((*arg, *o)),
            }
        }
    }
    found.ok_or_else(|| format!("--{name} is no option of the tool (it refuses it)"))
}

/// `true` when `arg` names a file rather than a module: a path, or a
/// module image's name.
fn names_a_file(arg: &str) -> bool {
    arg.contains('/')
        || [".ko", ".ko.xz", ".ko.zst", ".ko.gz"]
            .iter()
            .any(|s| arg.ends_with(s))
}

fn modprobe(args: &[String]) -> Syntax {
    let kill = |why: String| Syntax::Kill(format!("modprobe {why}"));
    if let Some(f) = args.iter().find(|a| names_a_file(a)) {
        return kill(format!(
            "given '{f}', which names a file, not a module of the system's tree"
        ));
    }
    let mut all = false;
    let mut names: Vec<&str> = Vec::new();
    let mut parameters = 0usize;
    let mut options_ended = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if let Some(first) = names.first() {
            if a.starts_with('-') {
                return kill(format!(
                    "given '{a}' after the module name '{first}': whether it is an option or a \
                     module parameter is the environment's to say (POSIXLY_CORRECT, \
                     MODPROBE_OPTIONS='--')"
                ));
            }
            if all {
                names.push(a);
            } else {
                parameters += 1;
            }
            continue;
        }
        if !options_ended && a == "--" {
            options_ended = true;
            continue;
        }
        if !options_ended {
            if let Some(body) = a.strip_prefix("--") {
                let (name, inline) = match body.split_once('=') {
                    Some((n, v)) => (n, Some(v)),
                    None => (body, None),
                };
                let (takes, opt) = match long_option(name) {
                    Ok(o) => o,
                    Err(why) => return kill(why),
                };
                if let Opt::Kill(why) = opt {
                    return kill(format!("{why}: '{a}'"));
                }
                match (takes, inline) {
                    (true, None) if it.next().is_none() => {
                        return kill(format!("--{name} has no argument (the tool refuses it)"))
                    }
                    (false, Some(_)) => {
                        return kill(format!("--{name} takes no argument (the tool refuses it)"))
                    }
                    _ => {}
                }
                all |= opt == Opt::All;
                continue;
            }
            if a.len() > 1 && a.starts_with('-') {
                for (i, c) in a[1..].char_indices() {
                    let Some((takes, opt)) = modprobe_short(c) else {
                        return kill(format!("-{c} is no option of the tool (it refuses it)"));
                    };
                    if let Opt::Kill(why) = opt {
                        return kill(format!("{why}: '{a}'"));
                    }
                    all |= opt == Opt::All;
                    if takes {
                        // its argument: the rest of the word, or the next one
                        if a[1 + i + c.len_utf8()..].is_empty() && it.next().is_none() {
                            return kill(format!("-{c} has no argument (the tool refuses it)"));
                        }
                        break;
                    }
                }
                continue;
            }
        }
        if a.starts_with('-') {
            return kill(format!(
                "given the module name '{a}', which starts with '-'"
            ));
        }
        names.push(a);
    }
    if names.is_empty() {
        return Syntax::Record("modprobe with no module named (a query or a usage error)".into());
    }
    let quoted: Vec<String> = names.iter().map(|n| format!("'{n}'")).collect();
    Syntax::Record(format!(
        "modprobe of {}{}",
        quoted.join(", "),
        match parameters {
            0 => String::new(),
            1 => " with 1 parameter".to_string(),
            n => format!(" with {n} parameters"),
        }
    ))
}

/// `kmod [options] <command>`: getopt with `+` (options stop at the first
/// operand), then the command.
fn kmod(args: &[String]) -> Syntax {
    let Some(first) = args.first() else {
        return Syntax::Record("kmod with no command (a usage error)".to_string());
    };
    match first.as_str() {
        "-h" | "--help" | "help" => Syntax::Record("kmod: the help printed".to_string()),
        "-V" | "--version" => Syntax::Record("kmod: the version printed".to_string()),
        "list" => Syntax::Record("kmod list (lsmod)".to_string()),
        "static-nodes" => Syntax::Record(
            "kmod static-nodes (the device nodes of modules, written for tmpfiles)".to_string(),
        ),
        other => Syntax::Kill(format!(
            "kmod command '{other}' is not one that loads nothing (help, list, static-nodes, \
             the version)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    fn modprobe_of(a: &[&str]) -> Syntax {
        judge(Tool::Modprobe, &v(a))
    }

    fn killed(s: &Syntax) -> Option<&str> {
        match s {
            Syntax::Kill(why) => Some(why),
            Syntax::Record(_) => None,
        }
    }

    #[test]
    fn the_tool_is_the_system_s_and_kmod_runs_as_argv0() {
        let t = |image, a: &[&str]| tool_of(image, &v(a));
        assert_eq!(
            t("/usr/bin/kmod", &["/sbin/modprobe", "x"]),
            Ok(Tool::Modprobe)
        );
        assert_eq!(t("/usr/bin/kmod", &["insmod", "x"]), Ok(Tool::Insmod));
        assert_eq!(t("/usr/bin/kmod", &["kmod", "list"]), Ok(Tool::Kmod));
        assert_eq!(t("/usr/bin/kmod", &["lsmod"]), Ok(Tool::Other("lsmod")));
        assert_eq!(t("/sbin/modprobe", &["modprobe", "x"]), Ok(Tool::Modprobe));
        assert_eq!(
            t("/usr/sbin/insmod", &["/usr/sbin/insmod"]),
            Ok(Tool::Insmod)
        );
        // a modprobe file run as insmod: kmod (a hard link) would be insmod
        assert!(t("/sbin/modprobe", &["insmod", "x"]).is_err());
        assert!(t("/usr/sbin/insmod", &["modprobe", "x"]).is_err());
        for bad in [
            "/tmp/modprobe",
            "/usr/local/sbin/modprobe",
            "/usr/lib/x/modprobe",
            "/usr/sbin/nn-modld",
            "/usr/sbin/modprobe (deleted)",
            "/usr/bin/kmod (deleted)",
            "modprobe",
            "/usr/bin/",
            // a subdirectory of a tool directory is not one
            "/usr/bin/x/modprobe",
            "/sbin/sub/kmod",
        ] {
            assert!(t(bad, &["modprobe", "x"]).is_err(), "{bad}");
        }
        // the other kmod modes' files are no module tool, whatever argv[0]
        for (image, arg0) in [("/usr/sbin/lsmod", "lsmod"), ("/usr/sbin/depmod", "depmod")] {
            assert!(t(image, &[arg0]).is_err(), "{image}");
        }
        assert!(t("/usr/bin/kmod", &[]).is_err(), "no argv");
        assert!(t("/usr/bin/kmod", &["modprobe.real", "x"]).is_err());
    }

    /// The container runtimes', kube-proxy's, k3s's, DKMS's and an
    /// administrator's shapes: module names, recorded, the names said.
    #[test]
    fn modprobe_by_name_is_recorded() {
        for (a, what) in [
            (&["modprobe", "nf_tables"][..], "modprobe of 'nf_tables'"),
            (&["/sbin/modprobe", "ip_tables"], "modprobe of 'ip_tables'"),
            (
                &["modprobe", "nf_conntrack", "hashsize=1024"],
                "modprobe of 'nf_conntrack' with 1 parameter",
            ),
            (
                &["modprobe", "-va", "bridge", "br_netfilter"],
                "modprobe of 'bridge', 'br_netfilter'",
            ),
            (
                &["modprobe", "--all", "--quiet", "a", "b"],
                "modprobe of 'a', 'b'",
            ),
            (&["modprobe", "--", "ip_vs"], "modprobe of 'ip_vs'"),
            (
                &["modprobe", "-q", "--", "nft-expr-counter"],
                "'nft-expr-counter'",
            ),
            (&["modprobe", "-w100", "-r", "nf_tables"], "'nf_tables'"),
            (&["modprobe", "-w", "100", "-r", "nf_tables"], "'nf_tables'"),
            (&["modprobe", "--wait=100", "-r", "x"], "'x'"),
            (&["modprobe", "--wait", "100", "-r", "x"], "'x'"),
            (&["modprobe", "-r", "dummy"], "'dummy'"),
            (&["modprobe", "-n", "-v", "nf_tables"], "'nf_tables'"),
            (&["modprobe", "-R", "fs-overlay"], "'fs-overlay'"),
            (&["modprobe", "-D", "dummy"], "'dummy'"),
            (&["modprobe", "-ib", "--first-time", "dummy"], "'dummy'"),
            (&["modprobe", "--show-depends", "ext4"], "'ext4'"),
            // an abbreviation of options of one meaning is that meaning
            (&["modprobe", "--show-c", "x"], "'x'"),
            (&["modprobe", "--qu", "x"], "'x'"),
            (&["modprobe", "-c"], "no module named"),
            (&["modprobe", "-V"], "no module named"),
            (&["modprobe", "--help"], "no module named"),
            (&["modprobe"], "no module named"),
            (&["modprobe", "-q"], "no module named"),
        ] {
            match modprobe_of(a) {
                Syntax::Record(w) => assert!(w.contains(what), "{a:?}: {w}"),
                k => panic!("{a:?}: {k:?}"),
            }
        }
    }

    /// The review of #498: the shapes that load what the system's tree does
    /// not name, or that the environment can turn into one, are killed —
    /// each by its option, short, long and abbreviated.
    #[test]
    fn a_file_a_moved_tree_a_forced_load_or_holders_is_killed() {
        for (a, why) in [
            (&["modprobe", "/tmp/rk.ko"][..], "names a file"),
            (&["modprobe", "./rk"], "names a file"),
            (&["modprobe", "rk.ko"], "names a file"),
            (&["modprobe", "rk.ko.zst"], "names a file"),
            (&["modprobe", "rk.ko.xz"], "names a file"),
            (&["modprobe", "rk.ko.gz"], "names a file"),
            (&["modprobe", "-a", "nf_tables", "rk.ko.xz"], "names a file"),
            (&["modprobe", "nf_conntrack", "x=/tmp/y"], "names a file"),
            (
                &["modprobe", "--dump-modversions", "/tmp/x.ko"],
                "names a file",
            ),
            (&["modprobe", "-d", "root", "nf_tables"], DIRNAME),
            (&["modprobe", "-droot", "nf_tables"], DIRNAME),
            (&["modprobe", "-qd", "root", "nf_tables"], DIRNAME),
            (&["modprobe", "--dirname=root", "nf_tables"], DIRNAME),
            (&["modprobe", "--dir", "root", "nf_tables"], DIRNAME),
            (&["modprobe", "-C", "x.conf", "nf_tables"], CONFIG),
            (&["modprobe", "--conf=x.conf", "nf_tables"], CONFIG),
            (&["modprobe", "--c", "x.conf", "nf_tables"], CONFIG),
            (&["modprobe", "-S", "9.9.9", "nf_tables"], SET_VERSION),
            (&["modprobe", "--set-version", "9.9.9", "x"], SET_VERSION),
            (&["modprobe", "--se=9.9.9", "x"], SET_VERSION),
            (
                &[
                    "modprobe",
                    "--all",
                    "--set-version=6.8.0-1",
                    "--ignore-install",
                    "--quiet",
                    "--show-depends",
                    "ext4",
                ],
                SET_VERSION,
            ),
            (&["modprobe", "-f", "nf_tables"], FORCE),
            (&["modprobe", "-vf", "nf_tables"], FORCE),
            (&["modprobe", "--force", "x"], FORCE),
            (&["modprobe", "--force-vermagic", "x"], FORCE),
            (&["modprobe", "--force-modversion", "x"], FORCE),
            (&["modprobe", "--forc", "x"], FORCE),
            (&["modprobe", "-o", "y", "x"], RENAME),
            (&["modprobe", "--remove-holders", "dummy"], HOLDERS),
            (&["modprobe", "--remove-dependencies", "dummy"], HOLDERS),
            (&["modprobe", "--remove-", "dummy"], HOLDERS),
            (&["modprobe", "--remove-h", "dummy"], HOLDERS),
            (&["modprobe", "-r", "--remove-holders", "dummy"], HOLDERS),
        ] {
            let s = modprobe_of(a);
            assert!(
                killed(&s).is_some_and(|w| w.contains(why)),
                "{a:?} ({why}): {s:?}"
            );
        }
    }

    /// The review of #498, B-4: an argument starting with `-` after the
    /// first name is killed — option or parameter, the environment decides
    /// (`POSIXLY_CORRECT`, `MODPROBE_OPTIONS='--'`); so is a name that
    /// starts with `-`.
    #[test]
    fn an_argument_starting_with_a_dash_after_the_name_is_killed() {
        for a in [
            &["modprobe", "dummy", "-r"][..],
            &["modprobe", "ip_tables", "-q"],
            &["modprobe", "dummy", "-n"],
            &["modprobe", "dummy", "--dry-run"],
            &["modprobe", "dummy", "-V"],
            &["modprobe", "dummy", "--"],
            &["modprobe", "-a", "a", "-b"],
            &["modprobe", "--all", "--", "a", "-b"],
            &["modprobe", "nf_conntrack", "hashsize=1", "-v"],
            &["modprobe", "-r", "dummy", "-w", "100"],
        ] {
            let s = modprobe_of(a);
            assert!(
                killed(&s).is_some_and(|w| w.contains("after the module name")),
                "{a:?}: {s:?}"
            );
        }
        for a in [&["modprobe", "--", "-r"][..], &["modprobe", "-"]] {
            let s = modprobe_of(a);
            assert!(
                killed(&s).is_some_and(|w| w.contains("starts with '-'")),
                "{a:?}: {s:?}"
            );
        }
    }

    #[test]
    fn what_the_tool_itself_refuses_is_killed() {
        for (a, why) in [
            (&["modprobe", "-Z", "x"][..], "-Z is no option"),
            (&["modprobe", "--bogus", "x"], "--bogus is no option"),
            // remove, remove-dependencies, remove-holders: two meanings
            (&["modprobe", "--remov", "x"], "ambiguous"),
            (&["modprobe", "--s", "x"], "ambiguous"),
            (&["modprobe", "--d", "x"], "ambiguous"),
            (&["modprobe", "-w"], "-w has no argument"),
            (&["modprobe", "--wait"], "--wait has no argument"),
            (&["modprobe", "--quiet=1", "x"], "takes no argument"),
        ] {
            let s = modprobe_of(a);
            assert!(
                killed(&s).is_some_and(|w| w.contains(why)),
                "{a:?} ({why}): {s:?}"
            );
        }
        // an exact name beats its longer neighbours
        assert!(matches!(
            modprobe_of(&["modprobe", "--show", "x"]),
            Syntax::Record(_)
        ));
        assert!(matches!(
            modprobe_of(&["modprobe", "--remove", "x"]),
            Syntax::Record(_)
        ));
    }

    #[test]
    fn insmod_is_always_killed() {
        let i = |a: &[&str]| judge(Tool::Insmod, &v(a));
        for (a, file) in [
            (&["insmod", "/tmp/rk.ko"][..], Some("/tmp/rk.ko")),
            (&["insmod", "rk.ko"], Some("rk.ko")),
            (
                &["insmod", "-f", "/lib/modules/6.8.0/kernel/x.ko"],
                Some("/lib/"),
            ),
            (&["insmod", "nf_tables"], Some("nf_tables")),
            (&["insmod"], None),
            (&["insmod", "-V"], None),
        ] {
            let s = i(a);
            let why = killed(&s).unwrap_or_else(|| panic!("{a:?}: {s:?}"));
            assert!(why.contains("insmod loads the file"), "{why}");
            if let Some(f) = file {
                assert!(why.contains(f), "{why}");
            }
        }
    }

    #[test]
    fn kmod_s_commands_that_load_nothing_are_recorded() {
        let k = |a: &[&str]| judge(Tool::Kmod, &v(a));
        for a in [
            &["kmod", "list"][..],
            &[
                "kmod",
                "static-nodes",
                "--format=tmpfiles",
                "--output=/run/tmpfiles.d/static-nodes.conf",
            ],
            &["kmod", "-V"],
            &["kmod", "--version"],
            &["kmod", "help"],
            &["kmod", "-h"],
            &["kmod", "--help"],
            &["kmod"],
        ] {
            assert!(matches!(k(a), Syntax::Record(_)), "{a:?}");
        }
        for a in [
            &["kmod", "insert", "x"][..],
            &["kmod", "modprobe", "x"],
            &["kmod", "-x"],
        ] {
            assert!(
                killed(&k(a)).is_some_and(|w| w.contains("not one that loads nothing")),
                "{a:?}"
            );
        }
        for mode in ["lsmod", "rmmod", "modinfo", "depmod"] {
            assert!(
                matches!(
                    judge(Tool::Other(mode), &v(&[mode, "x"])),
                    Syntax::Record(w) if w.contains(mode)
                ),
                "{mode}"
            );
        }
    }
}
