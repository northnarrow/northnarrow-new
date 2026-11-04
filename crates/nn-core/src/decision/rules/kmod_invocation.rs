//! Lot 279: what an exec of a kernel-module tool asks the tool to do, read
//! from its command line as the tool reads it (kmod 29..=34: `tools/kmod.c`,
//! `tools/modprobe.c`, `tools/insmod.c`). No I/O: the names it asks for are
//! resolved against the module tree by [`super::module_request`].
//!
//! - **kmod is a multi-call binary**: `insmod`, `modprobe`, `lsmod`, `rmmod`,
//!   `modinfo` and `depmod` are links to `/usr/bin/kmod`, which runs as the
//!   basename of `argv[0]` (`program_invocation_short_name`), not as the name
//!   of the file executed: `execve("/usr/bin/kmod", ["insmod", …])` is an
//!   insmod whose `comm` is `kmod`. As `kmod` it runs the subcommand
//!   `argv[1]` (`help`, `list`, `static-nodes`; `insert`/`remove` in an
//!   experimental build).
//! - **modprobe** parses its options with `getopt_long` (GNU: options are
//!   taken anywhere before `--`, long names by any unambiguous prefix). The
//!   first operand is the module, the rest its parameters; with `-a` every
//!   operand is a module.
//! - **insmod** loads the FILE its first operand names (a path, relative to
//!   the working directory when it has no `/`).
//!
//! What the caller chose is all here: the tool acts on the same `argv`
//! (the sensor reads it from the new image's argument area at the exec,
//! before the program runs). What the tool also reads and this does not see
//! is its environment (`MODPROBE_OPTIONS`, options added in front of these)
//! and its configuration files; [`super::module_request`] says why a load
//! they redirect is still judged (R018, on the file the kernel reads).

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

/// What an invocation asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Invocation {
    /// It loads no module: a query, a removal, a dry run, a usage error.
    LoadsNothing(String),
    /// `modprobe` of these module names (or aliases), in order.
    Modules(Vec<String>),
    /// It cannot be vouched for without resolving anything: a file to
    /// load, an option that moves the module tree or forces the load, an
    /// argument the tool would not parse as this does.
    Refused(String),
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
/// another name is no module tool). For `kmod` the mode is `argv[0]`'s
/// basename. A `modprobe` or `insmod` file is a link to kmod on every
/// distribution this runs on — a hard link shows its own name, not kmod's —
/// or a tool of that one name: `argv[0]` must name it too, so both readings
/// agree.
pub fn tool_of(image: &str, argv: &[String]) -> Result<Tool, String> {
    let in_tool_dir = TOOL_DIRS.iter().any(|d| {
        image
            .strip_prefix(d)
            .is_some_and(|rest| !rest.is_empty() && !rest.contains('/'))
    });
    if !in_tool_dir || image.ends_with(" (deleted)") {
        return Err(format!(
            "{image} is not the system's module tool (it lives outside /usr/bin, /usr/sbin, \
             /bin and /sbin)"
        ));
    }
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

/// What `tool` run with `argv` (`argv[0]` first) asks for.
pub fn parse(tool: Tool, argv: &[String]) -> Invocation {
    let args = argv.get(1..).unwrap_or_default();
    match tool {
        Tool::Modprobe => modprobe(args),
        Tool::Insmod => insmod(args),
        Tool::Kmod => kmod(args),
        Tool::Other(mode) => Invocation::LoadsNothing(format!("kmod run as {mode}")),
    }
}

/// What one of modprobe's options does to the load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Effect {
    /// Every operand is a module (`-a`).
    All,
    /// Nothing is inserted (a removal, a query, a dry run, the version or
    /// the help).
    NoLoad(&'static str),
    /// The module tree, the configuration or the kernel version the names
    /// are resolved against is the caller's (`-C`, `-d`, `-S`).
    Moves(&'static str),
    /// The kernel's version checks are skipped (`-f` and its long forms).
    Forces,
    /// Changes nothing this judges (`-q`, `-v`, `-s`, `-b`, `-i`,
    /// `--first-time`, `-w` of a removal).
    Neutral,
}

/// modprobe's long options (kmod 29..=34), with whether each takes an
/// argument.
const MODPROBE_LONG: &[(&str, bool, Effect)] = &[
    ("all", false, Effect::All),
    ("remove", false, Effect::NoLoad("a removal")),
    ("remove-dependencies", false, Effect::NoLoad("a removal")),
    ("remove-holders", false, Effect::NoLoad("a removal")),
    ("wait", true, Effect::Neutral),
    (
        "resolve-alias",
        false,
        Effect::NoLoad("an alias resolved and printed"),
    ),
    ("first-time", false, Effect::Neutral),
    ("ignore-install", false, Effect::Neutral),
    ("ignore-remove", false, Effect::Neutral),
    ("use-blacklist", false, Effect::Neutral),
    ("force", false, Effect::Forces),
    ("force-modversion", false, Effect::Forces),
    ("force-vermagic", false, Effect::Forces),
    (
        "show-depends",
        false,
        Effect::NoLoad("the dependencies printed"),
    ),
    (
        "showconfig",
        false,
        Effect::NoLoad("the configuration printed"),
    ),
    (
        "show-config",
        false,
        Effect::NoLoad("the configuration printed"),
    ),
    (
        "show-modversions",
        false,
        Effect::NoLoad("a module's versions printed"),
    ),
    (
        "dump-modversions",
        false,
        Effect::NoLoad("a module's versions printed"),
    ),
    (
        "show-exports",
        false,
        Effect::NoLoad("a module's exports printed"),
    ),
    ("dry-run", false, Effect::NoLoad("a dry run")),
    ("show", false, Effect::NoLoad("a dry run")),
    ("config", true, Effect::Moves("its configuration")),
    ("dirname", true, Effect::Moves("the module tree's root")),
    ("set-version", true, Effect::Moves("the kernel version")),
    ("syslog", false, Effect::Neutral),
    ("quiet", false, Effect::Neutral),
    ("verbose", false, Effect::Neutral),
    ("version", false, Effect::NoLoad("the version printed")),
    ("help", false, Effect::NoLoad("the help printed")),
];

/// modprobe's short option `c`: whether it takes an argument, what it does.
fn modprobe_short(c: char) -> Option<(bool, Effect)> {
    Some(match c {
        'a' => (false, Effect::All),
        'r' => (false, Effect::NoLoad("a removal")),
        'w' => (true, Effect::Neutral),
        'R' => (false, Effect::NoLoad("an alias resolved and printed")),
        'i' | 'b' | 's' | 'q' | 'v' => (false, Effect::Neutral),
        'f' => (false, Effect::Forces),
        'D' => (false, Effect::NoLoad("the dependencies printed")),
        'c' => (false, Effect::NoLoad("the configuration printed")),
        'n' => (false, Effect::NoLoad("a dry run")),
        'C' => (true, Effect::Moves("its configuration")),
        'd' => (true, Effect::Moves("the module tree's root")),
        'S' => (true, Effect::Moves("the kernel version")),
        'V' => (false, Effect::NoLoad("the version printed")),
        'h' => (false, Effect::NoLoad("the help printed")),
        _ => return None,
    })
}

/// A long option as `getopt_long` matches it: the exact name, else the one
/// option the prefix names (several names of the same meaning are one).
fn long_option(
    table: &'static [(&'static str, bool, Effect)],
    name: &str,
) -> Result<(bool, Effect), String> {
    if let Some((_, arg, e)) = table.iter().find(|(n, _, _)| *n == name) {
        return Ok((*arg, *e));
    }
    let mut found: Option<(bool, Effect)> = None;
    for (n, arg, e) in table {
        if n.starts_with(name) {
            match found {
                Some(f) if f != (*arg, *e) => {
                    return Err(format!("--{name} is ambiguous (the tool refuses it)"));
                }
                _ => found = Some((*arg, *e)),
            }
        }
    }
    found.ok_or_else(|| format!("--{name} is no option of the tool (it refuses it)"))
}

/// The options' effects (each with its argument, or empty) and the
/// operands, in order.
type Parsed = (Vec<(Effect, String)>, Vec<String>);

/// The options and operands of `args` as `getopt_long` permutes them: the
/// effects in order, the operands in order. `Err` for what the tool itself
/// refuses (an unknown or ambiguous option, a missing argument).
fn getopt(
    args: &[String],
    short: impl Fn(char) -> Option<(bool, Effect)>,
    long: &'static [(&'static str, bool, Effect)],
) -> Result<Parsed, String> {
    let mut effects = Vec::new();
    let mut operands = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--" {
            operands.extend(it.by_ref().cloned());
            break;
        }
        if let Some(body) = a.strip_prefix("--") {
            let (name, inline) = match body.split_once('=') {
                Some((n, v)) => (n, Some(v)),
                None => (body, None),
            };
            let (takes, e) = long_option(long, name)?;
            let value = match (takes, inline) {
                (true, Some(v)) => v.to_string(),
                (true, None) => it
                    .next()
                    .cloned()
                    .ok_or_else(|| format!("--{name} has no argument (the tool refuses it)"))?,
                (false, Some(_)) => {
                    return Err(format!("--{name} takes no argument (the tool refuses it)"))
                }
                (false, None) => String::new(),
            };
            effects.push((e, value));
            continue;
        }
        if a.len() > 1 && a.starts_with('-') {
            for (i, c) in a[1..].char_indices() {
                let (takes, e) = short(c)
                    .ok_or_else(|| format!("-{c} is no option of the tool (it refuses it)"))?;
                if takes {
                    let rest = &a[1 + i + c.len_utf8()..];
                    let value = if rest.is_empty() {
                        it.next()
                            .cloned()
                            .ok_or_else(|| format!("-{c} has no argument (the tool refuses it)"))?
                    } else {
                        rest.to_string()
                    };
                    effects.push((e, value));
                    break;
                }
                effects.push((e, String::new()));
            }
            continue;
        }
        operands.push(a.clone());
    }
    Ok((effects, operands))
}

/// `true` when `operand` names a file rather than a module: a path, or a
/// module image's name.
fn names_a_file(operand: &str) -> bool {
    operand.contains('/')
        || [".ko", ".ko.xz", ".ko.zst", ".ko.gz"]
            .iter()
            .any(|s| operand.ends_with(s))
}

fn modprobe(args: &[String]) -> Invocation {
    let (effects, operands) = match getopt(args, modprobe_short, MODPROBE_LONG) {
        Ok(p) => p,
        Err(why) => return Invocation::Refused(format!("modprobe {why}")),
    };
    // Nothing is inserted whatever tree or configuration it reads.
    if let Some((Effect::NoLoad(what), _)) =
        effects.iter().find(|(e, _)| matches!(e, Effect::NoLoad(_)))
    {
        return Invocation::LoadsNothing(format!("modprobe: {what}"));
    }
    if let Some((Effect::Moves(what), value)) =
        effects.iter().find(|(e, _)| matches!(e, Effect::Moves(_)))
    {
        return Invocation::Refused(format!(
            "modprobe told to take {what} from the caller ('{value}'): the module it loads is \
             not the one the system's tree names"
        ));
    }
    if effects.iter().any(|(e, _)| *e == Effect::Forces) {
        return Invocation::Refused(
            "modprobe told to force the load past the kernel's version checks, which no \
             module of the running kernel's tree needs"
                .to_string(),
        );
    }
    let all = effects.iter().any(|(e, _)| *e == Effect::All);
    let names: Vec<String> = if all {
        operands
    } else {
        operands.into_iter().take(1).collect()
    };
    if names.is_empty() {
        return Invocation::LoadsNothing("modprobe: no module named (a usage error)".to_string());
    }
    if let Some(f) = names.iter().find(|n| names_a_file(n)) {
        return Invocation::Refused(format!(
            "modprobe asked to load the file '{f}', not a module of the system's tree"
        ));
    }
    Invocation::Modules(names)
}

/// insmod's options (kmod 29..=34).
const INSMOD_LONG: &[(&str, bool, Effect)] = &[
    ("force", false, Effect::Neutral),
    ("syslog", false, Effect::Neutral),
    ("verbose", false, Effect::Neutral),
    ("version", false, Effect::NoLoad("the version printed")),
    ("help", false, Effect::NoLoad("the help printed")),
];

fn insmod_short(c: char) -> Option<(bool, Effect)> {
    Some(match c {
        'p' | 's' | 'f' | 'v' => (false, Effect::Neutral),
        'V' => (false, Effect::NoLoad("the version printed")),
        'h' => (false, Effect::NoLoad("the help printed")),
        _ => return None,
    })
}

fn insmod(args: &[String]) -> Invocation {
    let (effects, operands) = match getopt(args, insmod_short, INSMOD_LONG) {
        Ok(p) => p,
        Err(why) => return Invocation::Refused(format!("insmod {why}")),
    };
    if let Some((Effect::NoLoad(what), _)) =
        effects.iter().find(|(e, _)| matches!(e, Effect::NoLoad(_)))
    {
        return Invocation::LoadsNothing(format!("insmod: {what}"));
    }
    match operands.first() {
        Some(file) => Invocation::Refused(format!(
            "insmod loads the file '{file}' as given, which no module tree resolves"
        )),
        None => Invocation::LoadsNothing("insmod: no file named (a usage error)".to_string()),
    }
}

/// `kmod [options] <command>`: getopt with `+` (options stop at the first
/// operand), then the command.
fn kmod(args: &[String]) -> Invocation {
    let Some(first) = args.first() else {
        return Invocation::LoadsNothing("kmod: no command (a usage error)".to_string());
    };
    match first.as_str() {
        "-h" | "--help" | "help" => Invocation::LoadsNothing("kmod: the help printed".to_string()),
        "-V" | "--version" => Invocation::LoadsNothing("kmod: the version printed".to_string()),
        "list" => Invocation::LoadsNothing("kmod list (lsmod)".to_string()),
        "static-nodes" => Invocation::LoadsNothing(
            "kmod static-nodes (the device nodes of modules, written for tmpfiles)".to_string(),
        ),
        other => Invocation::Refused(format!(
            "kmod command '{other}' is not one that loads nothing (help, list, static-nodes)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    fn modprobe_of(a: &[&str]) -> Invocation {
        parse(Tool::Modprobe, &v(a))
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
            "modprobe",
            "/usr/bin/",
        ] {
            assert!(t(bad, &["modprobe", "x"]).is_err(), "{bad}");
        }
        assert!(t("/usr/bin/kmod", &[]).is_err(), "no argv");
        assert!(t("/usr/bin/kmod", &["modprobe.real", "x"]).is_err());
    }

    #[test]
    fn modprobe_names_are_the_first_operand_or_all_with_a() {
        assert_eq!(
            modprobe_of(&["modprobe", "nf_tables"]),
            Invocation::Modules(v(&["nf_tables"]))
        );
        // xtables_insmod: the option after the name (getopt permutes)
        assert_eq!(
            modprobe_of(&["/sbin/modprobe", "ip_tables", "-q"]),
            Invocation::Modules(v(&["ip_tables"]))
        );
        assert_eq!(
            modprobe_of(&["modprobe", "nf_conntrack", "hashsize=1024"]),
            Invocation::Modules(v(&["nf_conntrack"]))
        );
        // docker: modprobe -va
        assert_eq!(
            modprobe_of(&["modprobe", "-va", "bridge", "br_netfilter"]),
            Invocation::Modules(v(&["bridge", "br_netfilter"]))
        );
        assert_eq!(
            modprobe_of(&["modprobe", "--all", "--quiet", "--", "a", "-b"]),
            Invocation::Modules(v(&["a", "-b"]))
        );
        assert_eq!(
            modprobe_of(&["modprobe", "--", "ip_vs"]),
            Invocation::Modules(v(&["ip_vs"]))
        );
    }

    #[test]
    fn a_file_or_a_moved_tree_is_refused_before_any_lookup() {
        for a in [
            &["modprobe", "/tmp/rk.ko"][..],
            &["modprobe", "./rk"],
            &["modprobe", "rk.ko"],
            &["modprobe", "rk.ko.zst"],
            &["modprobe", "-a", "nf_tables", "rk.ko.xz"],
            &["modprobe", "-d", "/tmp/root", "nf_tables"],
            &["modprobe", "-d/tmp/root", "nf_tables"],
            &["modprobe", "-qd", "/tmp/root", "nf_tables"],
            &["modprobe", "--dirname=/tmp/root", "nf_tables"],
            &["modprobe", "--dir", "/tmp/root", "nf_tables"],
            &["modprobe", "-C", "/tmp/x.conf", "nf_tables"],
            &["modprobe", "--conf=/tmp/x.conf", "nf_tables"],
            &["modprobe", "-S", "9.9.9", "nf_tables"],
            &["modprobe", "--set-version", "9.9.9", "nf_tables"],
            &["modprobe", "-f", "nf_tables"],
            &["modprobe", "--force-vermagic", "nf_tables"],
            &["modprobe", "nf_tables", "--force"],
        ] {
            assert!(
                matches!(modprobe_of(a), Invocation::Refused(_)),
                "{a:?}: {:?}",
                modprobe_of(a)
            );
        }
    }

    #[test]
    fn what_the_tool_itself_refuses_is_refused() {
        for a in [
            &["modprobe", "-Z", "x"][..],
            &["modprobe", "--bogus", "x"],
            &["modprobe", "--s", "x"],
            &["modprobe", "-C"],
            &["modprobe", "--quiet=1", "x"],
        ] {
            assert!(
                matches!(modprobe_of(a), Invocation::Refused(_)),
                "{a:?}: {:?}",
                modprobe_of(a)
            );
        }
        // the same meaning under two names is no ambiguity
        assert!(matches!(
            modprobe_of(&["modprobe", "--remove-", "x"]),
            Invocation::LoadsNothing(_)
        ));
        // an exact name beats its longer neighbours
        assert!(matches!(
            modprobe_of(&["modprobe", "--show", "x"]),
            Invocation::LoadsNothing(_)
        ));
    }

    /// initramfs-tools' `manual_add_modules`: `modprobe --all --set-version=V
    /// --ignore-install --quiet --show-depends` inserts nothing, whatever
    /// version it reads.
    #[test]
    fn a_query_loads_nothing_whatever_tree_it_reads() {
        for a in [
            &[
                "modprobe",
                "--all",
                "--set-version=6.8.0-1",
                "--ignore-install",
                "--quiet",
                "--show-depends",
                "ext4",
            ][..],
            &["modprobe", "-r", "dummy"],
            &["modprobe", "-rv", "-C", "/tmp/x.conf", "dummy"],
            &["modprobe", "-n", "-v", "nf_tables"],
            &["modprobe", "-R", "fs-overlay"],
            &["modprobe", "-c"],
            &["modprobe", "--dump-modversions", "/tmp/x.ko"],
            &["modprobe", "-V"],
            &["modprobe", "--help"],
            &["modprobe"],
            &["modprobe", "-q"],
        ] {
            assert!(
                matches!(modprobe_of(a), Invocation::LoadsNothing(_)),
                "{a:?}: {:?}",
                modprobe_of(a)
            );
        }
    }

    #[test]
    fn insmod_always_loads_a_file() {
        let i = |a: &[&str]| parse(Tool::Insmod, &v(a));
        for a in [
            &["insmod", "/tmp/rk.ko"][..],
            &["insmod", "rk.ko"],
            &["insmod", "-f", "/lib/modules/6.8.0/kernel/x.ko"],
            &["insmod", "nf_tables"],
        ] {
            assert!(matches!(i(a), Invocation::Refused(_)), "{a:?}");
        }
        for a in [
            &["insmod"][..],
            &["insmod", "-V"],
            &["insmod", "--help", "x.ko"],
        ] {
            assert!(matches!(i(a), Invocation::LoadsNothing(_)), "{a:?}");
        }
        assert!(matches!(i(&["insmod", "-Z", "x"]), Invocation::Refused(_)));
    }

    #[test]
    fn kmod_s_commands_that_load_nothing() {
        let k = |a: &[&str]| parse(Tool::Kmod, &v(a));
        for a in [
            &["kmod", "list"][..],
            &[
                "kmod",
                "static-nodes",
                "--format=tmpfiles",
                "--output=/run/x",
            ],
            &["kmod", "-V"],
            &["kmod", "help"],
            &["kmod"],
        ] {
            assert!(matches!(k(a), Invocation::LoadsNothing(_)), "{a:?}");
        }
        for a in [
            &["kmod", "insert", "x"][..],
            &["kmod", "modprobe", "x"],
            &["kmod", "-x"],
        ] {
            assert!(matches!(k(a), Invocation::Refused(_)), "{a:?}");
        }
        assert!(matches!(
            parse(Tool::Other("lsmod"), &v(&["lsmod"])),
            Invocation::LoadsNothing(_)
        ));
    }
}
