//! Lot 316: the system tools' tables, read as their parsers read them (the
//! cases from each tool's source and manual, `tool_options`' table).

use super::*;
use crate::posture::script_args::SIGNAL;

fn argv(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

/// One reading, owned: its options (name, arguments), its operands, and
/// whether it was understood.
type Owned = (Vec<(String, Vec<String>)>, Vec<String>, bool);

/// The readings of `a` (its `argv[0]` first) by `tool`'s table.
fn read(tool: SystemTool, a: &[&str]) -> Vec<Owned> {
    let v = argv(a);
    tool.read(&v, 1)
        .into_iter()
        .map(|r| {
            (
                r.options
                    .iter()
                    .map(|(n, v)| (n.to_string(), v.iter().map(|x| x.to_string()).collect()))
                    .collect(),
                r.operands.iter().map(|x| x.to_string()).collect(),
                r.understood,
            )
        })
        .collect()
}

/// The first (the tool's own) reading's operands, and whether it was
/// understood.
fn operands(tool: SystemTool, a: &[&str]) -> (Vec<String>, bool) {
    let r = read(tool, a);
    (r[0].1.clone(), r[0].2)
}

/// The first reading's arguments of option `name`.
fn option(tool: SystemTool, a: &[&str], name: &str) -> Option<Vec<String>> {
    read(tool, a)[0]
        .0
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.clone())
}

const ALL: [SystemTool; 7] = [
    SystemTool::Systemctl,
    SystemTool::Kill,
    SystemTool::Pkill,
    SystemTool::Killall,
    SystemTool::Iptables,
    SystemTool::Nft,
    SystemTool::FirewallCmd,
];

/// A long option and its letter are one option: read the same way.
#[test]
fn an_alias_is_read_as_its_letter() {
    for tool in ALL {
        let t = tool.table();
        for (long, c) in t.aliases {
            let (_, kind) = t
                .long
                .iter()
                .find(|(n, _)| n == long)
                .unwrap_or_else(|| panic!("{tool:?}: alias {long} not a long option"));
            let (_, opt) = t
                .short(*c)
                .unwrap_or_else(|| panic!("{tool:?}: {long}'s letter {c} not a short option"));
            let same = matches!(
                (kind, opt),
                (Long::Flag, Opt::Flag)
                    | (Long::Arg, Opt::Arg)
                    | (Long::Optional, Opt::Rest)
                    | (Long::Optional, Opt::OptionalNext)
                    | (Long::OptionalNext, Opt::OptionalNext)
                    | (Long::Arg2, Opt::Arg2)
            );
            assert!(same, "{tool:?}: --{long} {kind:?} but -{c} {opt:?}");
        }
    }
}

/// BUG-106: systemctl's options before the verb, as getopt_long reads
/// them: `-P` (with a value), the long options the old list missed, a
/// unique prefix (`--si`), a cluster ending in a valued letter (`-qs KILL`),
/// `--name=value`.
#[test]
fn systemctl_reads_its_options_as_getopt_long() {
    let s = SystemTool::Systemctl;
    for a in [
        &["systemctl", "-P", "Id", "stop", "auditd"][..],
        &["systemctl", "--preset-mode", "full", "stop", "auditd"],
        &["systemctl", "--check-inhibitors", "no", "stop", "auditd"],
        &["systemctl", "--kill-who", "main", "stop", "auditd"],
        &["systemctl", "--kill-whom=main", "stop", "auditd"],
        &["systemctl", "--message", "x", "stop", "auditd"],
        &["systemctl", "--si", "KILL", "stop", "auditd"],
        &["systemctl", "-qs", "KILL", "stop", "auditd"],
        &["systemctl", "-sKILL", "stop", "auditd"],
        &["systemctl", "--no-pager", "-q", "--now", "stop", "auditd"],
        &["systemctl", "stop", "-s", "KILL", "auditd"],
        &["systemctl", "--", "stop", "auditd"],
    ] {
        assert_eq!(operands(s, a), (argv(&["stop", "auditd"]), true), "{a:?}");
    }
    assert_eq!(
        option(s, &["systemctl", "--sig=TERM", "kill", "x"], "s"),
        Some(argv(&["TERM"]))
    );
    // a lone `-` is an operand
    assert_eq!(
        operands(s, &["systemctl", "stop", "-"]),
        (argv(&["stop", "-"]), true)
    );
    // an ambiguous prefix (`--no-` is many options) is not understood
    assert!(!operands(s, &["systemctl", "--no-", "stop", "auditd"]).1);
    // a flag with a value: getopt_long refuses it
    assert!(!operands(s, &["systemctl", "--now=yes", "stop", "auditd"]).1);
}

/// GNU getopt permutes: an option after the verb is an option, unless
/// `POSIXLY_CORRECT` is in the environment — both readings are given.
#[test]
fn systemctl_is_read_with_and_without_posixly_correct() {
    let r = read(
        SystemTool::Systemctl,
        &["systemctl", "stop", "auditd", "--user"],
    );
    assert_eq!(r.len(), 2, "{r:?}");
    assert_eq!(r[0].1, argv(&["stop", "auditd"]));
    assert!(r[0].0.iter().any(|(n, _)| n == "user"));
    assert_eq!(r[1].1, argv(&["stop", "auditd", "--user"]));
    // the same reading twice is given once
    assert_eq!(
        read(SystemTool::Systemctl, &["systemctl", "stop", "auditd"]).len(),
        1
    );
}

/// BUG-89: pkill's `-n`, `-o`, `-c` take no value (procps' optstring
/// `LF:cfinoxP:O:AHg:s:u:U:G:t:r:?Vh` and `eq:`), `-g` one; the first
/// `-SIGNAL` is the signal, in any case, by name or number.
#[test]
fn pkill_reads_its_options_as_procps() {
    let p = SystemTool::Pkill;
    for a in [
        &["pkill", "-n", "auditd"][..],
        &["pkill", "-o", "auditd"],
        &["pkill", "-c", "auditd"],
        &["pkill", "-9", "-n", "auditd"],
        &["pkill", "-KILL", "auditd"],
        &["pkill", "-sigkill", "auditd"],
        &["pkill", "--signal", "KILL", "auditd"],
        &["pkill", "--sig=9", "auditd"],
        &["pkill", "-g", "5", "auditd"],
        &["pkill", "-xf", "auditd"],
        &["pkill", "auditd", "-n"],
    ] {
        assert_eq!(operands(p, a), (argv(&["auditd"]), true), "{a:?}");
    }
    assert_eq!(
        option(p, &["pkill", "-HUP", "rsyslogd"], SIGNAL),
        Some(argv(&["HUP"]))
    );
    // in any case, with or without SIG, by number up to 64 (procps)
    for sig in ["hup", "sigkill", "SigTerm", "9", "64", "rtmin+3", "RTMAX-1"] {
        let a = format!("-{sig}");
        assert_eq!(
            option(p, &["pkill", &a, "x"], SIGNAL),
            Some(argv(&[sig])),
            "{sig}"
        );
    }
    for not in ["65", "sigfoo", "rtmin+", "s"] {
        let a = format!("-{not}");
        assert_eq!(option(p, &["pkill", &a, "x"], SIGNAL), None, "{not}");
    }
}

/// BUG-89: killall's `-g` (process group) takes no value; getopt_long_only
/// reads a long option with one hyphen (`-signal`, `-sig`); a capital
/// unknown to it is a signal.
#[test]
fn killall_reads_its_options_as_psmisc() {
    let k = SystemTool::Killall;
    for a in [
        &["killall", "-g", "auditd"][..],
        &["killall", "-e", "auditd"],
        &["killall", "-s", "KILL", "auditd"],
        &["killall", "-signal", "KILL", "auditd"],
        &["killall", "-sig", "KILL", "auditd"],
        &["killall", "--signal=KILL", "auditd"],
        &["killall", "-KILL", "auditd"],
        &["killall", "-9", "auditd"],
        &["killall", "-eg", "auditd"],
        &["killall", "-u", "root", "auditd"],
        &["killall", "-o", "5m", "auditd"],
    ] {
        assert_eq!(operands(k, a), (argv(&["auditd"]), true), "{a:?}");
    }
    assert_eq!(
        option(k, &["killall", "-sig", "KILL", "x"], "s"),
        Some(argv(&["KILL"]))
    );
    // `-i` is a letter (interactive), `-ig` a prefix of `--ignore-case`
    assert!(read(k, &["killall", "-i", "x"])[0]
        .0
        .iter()
        .any(|(n, _)| n == "i"));
    assert!(read(k, &["killall", "-ig", "x"])[0]
        .0
        .iter()
        .any(|(n, _)| n == "I"));
}

/// N4: iptables' policy with its long name, a prefix of it, the chain
/// attached; its flush with the chain attached, separate, `=`, or none; an
/// argument that starts with `-` is no chain; `!` inverts.
#[test]
fn iptables_reads_its_commands_as_xtables() {
    let i = SystemTool::Iptables;
    let policy = argv(&["INPUT", "ACCEPT"]);
    for a in [
        &["iptables", "-P", "INPUT", "ACCEPT"][..],
        &["iptables", "--policy", "INPUT", "ACCEPT"],
        &["iptables", "--pol", "INPUT", "ACCEPT"],
        &["iptables", "--policy=INPUT", "ACCEPT"],
        &["iptables", "-PINPUT", "ACCEPT"],
        &["iptables", "-w", "-t", "filter", "-P", "INPUT", "ACCEPT"],
        &["iptables", "-P", "INPUT", "ACCEPT", "-w", "5"],
    ] {
        assert_eq!(option(i, a, "P"), Some(policy.clone()), "{a:?}");
    }
    for (a, chain) in [
        (&["iptables", "-F"][..], None),
        (&["iptables", "--flush"], None),
        (&["iptables", "--fl"], None),
        (&["iptables", "-F", "INPUT"], Some("INPUT")),
        (&["iptables", "-FINPUT"], Some("INPUT")),
        (&["iptables", "--flush=INPUT"], Some("INPUT")),
        (&["iptables", "--flush", "INPUT"], Some("INPUT")),
        (&["iptables", "-F", "-X"], None),
        (&["iptables", "-vF"], None),
        (&["iptables", "-w", "-F", "INPUT"], Some("INPUT")),
        (&["iptables", "-w", "5", "-F"], None),
        (&["iptables", "-t", "nat", "-F", "CNI-x"], Some("CNI-x")),
        // `!` is no chain (`xs_has_arg`)
        (&["iptables", "-F", "!", "-s", "10.0.0.1"], None),
    ] {
        let want: Vec<String> = chain.into_iter().map(String::from).collect();
        assert_eq!(option(i, a, IPTABLES_FLUSH), Some(want), "{a:?}");
    }
    // `--pol` is `--policy`, or the policy match's `--pol` when `-m policy`
    // loads it: not understood, and its reading holds both
    let r = read(i, &["iptables", "--pol", "INPUT", "ACCEPT"]);
    assert!(!r[0].2, "{r:?}");
    assert!(
        r[0].0.contains(&("pol".to_string(), argv(&["INPUT"]))),
        "{r:?}"
    );
    // `-P` with one argument, or a policy that starts with `-`: iptables
    // refuses it ("-P requires a chain and a policy")
    assert!(!operands(i, &["iptables", "-P", "INPUT"]).1);
    assert!(!operands(i, &["iptables", "-P", "INPUT", "-j"]).1);
    // `--f` is `--flush` or `--fragments`: refused
    assert!(!operands(i, &["iptables", "--f"]).1);
    // an extension's option takes its value, which starts with `-`: no flush
    let log = [
        "iptables",
        "-A",
        "INPUT",
        "!",
        "-s",
        "10.0.0.0/8",
        "-j",
        "LOG",
        "--log-prefix",
        "-FW-",
    ];
    let r = read(i, &log);
    assert!(r[0].2, "{r:?}");
    assert!(!r[0].0.iter().any(|(n, _)| n == IPTABLES_FLUSH), "{r:?}");
    // the `!` inverts the next match: no operand
    assert!(r[0].1.is_empty(), "{r:?}");
    // an extension's option the table does not hold: not understood
    assert!(!operands(i, &["iptables", "-A", "INPUT", "--nosuch", "x"]).1);
}

/// nft: the first operand ends its options (`+`), and its operands are one
/// command line, split on blanks and `;`.
#[test]
fn nft_reads_one_command_line() {
    let n = SystemTool::Nft;
    for a in [
        &["nft", "flush", "ruleset"][..],
        &["nft", "flush ruleset"],
        &["nft", "\tflush\n  ruleset "],
        &["nft", "-c", "flush", "ruleset"],
        &["nft", "--check", "--", "flush", "ruleset"],
    ] {
        assert_eq!(operands(n, a), (argv(&["flush", "ruleset"]), true), "{a:?}");
    }
    assert_eq!(
        operands(n, &["nft", "add table x;flush ruleset;"]).0,
        argv(&["add", "table", "x", ";", "flush", "ruleset", ";"])
    );
    // an option after the command is a word of it (nft refuses it)
    assert_eq!(
        operands(n, &["nft", "list", "ruleset", "-a"]).0,
        argv(&["list", "ruleset", "-a"])
    );
    assert_eq!(read(n, &["nft", "list", "ruleset", "-a"]).len(), 1);
}

/// N4: firewall-cmd's argparse reads `--name value`, `--name=value` and a
/// unique prefix; an ambiguous one is refused.
#[test]
fn firewall_cmd_reads_its_options_as_argparse() {
    let f = SystemTool::FirewallCmd;
    for a in [
        &["firewall-cmd", "--set-default-zone=trusted"][..],
        &["firewall-cmd", "--set-default-zone", "trusted"],
        &["firewall-cmd", "--set-def", "trusted"],
        &["firewall-cmd", "-q", "--set-default=trusted"],
    ] {
        assert_eq!(
            option(f, a, "set-default-zone"),
            Some(argv(&["trusted"])),
            "{a:?}"
        );
    }
    // `--set-d` is `--set-default-zone` or `--set-description`
    assert!(!operands(f, &["firewall-cmd", "--set-d", "trusted"]).1);
    // the direct interface's many-argument options are not read
    assert!(
        !operands(
            f,
            &["firewall-cmd", "--direct", "--add-rule", "ipv4", "filter"]
        )
        .1
    );
}

/// procps' kill: the first `-SIGNAL`, `-s`, `-l` (a listing).
#[test]
fn kill_reads_its_options_as_procps() {
    let k = SystemTool::Kill;
    assert_eq!(operands(k, &["kill", "-9", "77"]), (argv(&["77"]), true));
    assert_eq!(
        option(k, &["kill", "-s", "0", "77"], "s"),
        Some(argv(&["0"]))
    );
    assert_eq!(
        option(k, &["kill", "--signal=KILL", "77"], "s"),
        Some(argv(&["KILL"]))
    );
    assert!(read(k, &["kill", "-9", "77", "-l"])[0]
        .0
        .iter()
        .any(|(n, _)| n == "l"));
}

/// Every switch-off command of the shipped list for a tool with a table is
/// read by it, understood.
#[test]
fn the_listed_commands_are_understood() {
    let list = crate::impair::SecurityTools::builtin();
    let mut read_some = 0;
    for c in &list.cmds {
        if let Some(tool) = SystemTool::named(&c.program) {
            let r = read_listed(tool, &c.args);
            assert!(r.understood, "{} {:?}", c.program, c.args);
            assert!(
                !r.options.is_empty() || !r.operands.is_empty(),
                "{} {:?}",
                c.program,
                c.args
            );
            read_some += 1;
        }
    }
    assert!(read_some >= 7, "{read_some}");
}

/// The xtables multi-call binaries: the program `argv[0]` names, else the
/// one `argv[1]` names (`main4`, `iptables-nft`); `-nft` and `-legacy`
/// names are iptables.
#[test]
fn an_xtables_program_is_named_as_it_runs() {
    let of = |exe: &str, a: &[&str]| Program::of(Path::new(exe), &argv(a));
    let multi = "/usr/sbin/xtables-nft-multi";
    for (exe, a, from) in [
        (multi, &["iptables", "-F"][..], 1),
        (multi, &["iptables-nft", "-F"], 1),
        (multi, &["/usr/sbin/iptables", "-F"], 1),
        (multi, &["xtables-nft-multi", "iptables", "-F"], 2),
        (multi, &["xtables-nft-multi", "main4", "-F"], 2),
        (multi, &["anything", "iptables-nft", "-F"], 2),
        ("/usr/sbin/xtables-legacy-multi", &["x", "main4", "-F"], 2),
        (
            "/usr/sbin/xtables-legacy-multi",
            &["iptables-legacy", "-F"],
            1,
        ),
        ("/usr/sbin/iptables-legacy", &["iptables-legacy", "-F"], 1),
    ] {
        let p = of(exe, a);
        assert!(p.is("iptables"), "{exe} {a:?}: {p:?}");
        assert_eq!(p.args_from, from, "{exe} {a:?}");
        assert_eq!(p.tool(), Some(SystemTool::Iptables));
    }
    let p = of(multi, &["xtables-nft-multi", "main6", "-F"]);
    assert!(p.is("ip6tables") && !p.is("iptables"), "{p:?}");
    // its other programs are not iptables
    for a in [
        &["iptables-save"][..],
        &["iptables-restore"],
        &["xtables-nft-multi", "iptables-translate", "-F"],
    ] {
        assert!(!of(multi, a).is("iptables"), "{a:?}");
    }
    // a program that is no multi-call binary does not read argv[1]
    assert!(!of("/usr/bin/sudo", &["sudo", "iptables", "-F"]).is("iptables"));
}

/// Any short cluster or long word of up to three characters, through every
/// table, in every reading: no panic, and every operand and option value is
/// a part of the argv.
#[test]
fn any_argument_is_read_without_a_panic() {
    let alphabet: Vec<char> = "aceFfgiIklnoPpqsSTtuvwxX09-=!;é".chars().collect();
    let mut words = vec![String::new()];
    for _ in 0..3 {
        let mut next = Vec::new();
        for w in &words {
            for c in &alphabet {
                next.push(format!("{w}{c}"));
            }
        }
        words.extend(next);
    }
    for tool in ALL {
        for w in &words {
            for prefix in ["-", "--", ""] {
                let a = argv(&["x", &format!("{prefix}{w}"), "y"]);
                for r in tool.read(&a, 1) {
                    for o in &r.operands {
                        assert!(a.iter().any(|x| x.contains(o)), "{tool:?} {a:?} {o:?}");
                    }
                    for (_, v) in &r.options {
                        for x in v {
                            assert!(a.iter().any(|y| y.contains(x)), "{tool:?} {a:?}");
                        }
                    }
                }
            }
        }
    }
}
