//! Lot 316 (external bug hunt, edition 1.4: BUG-106, BUG-89, N4): the
//! option tables of the system tools a security tool is switched off with,
//! read by the one reader of [`crate::posture::script_args`]
//! ([`read_tool`]) — never by hand (`xtask/tests/interpreter_options.rs`).
//!
//! Each table is its tool's own parser, read from its source:
//!
//! | Tool | Parser | Source |
//! |---|---|---|
//! | `systemctl` | `getopt_long`, `"hC:t:p:P:alqfs:H:M:n:o:iTr.::"`, permuted | systemd 249–262 `systemctl.c` |
//! | `kill` | procps' `skill_sig_option` (the first `-SIGNAL`), then `getopt_long`, `"l::Ls:hVq:"` | procps-ng 4.0.4 `kill.c` |
//! | `pkill` | `signal_option` (the first `-SIGNAL`), then `getopt_long`, `"eq:LF:cfinoxP:O:AHg:s:u:U:G:t:r:?Vh"` | procps-ng 4.0.4 `pgrep.c` |
//! | `killall` | `getopt_long_only`, `"egy:o:ilqrs:u:vwZ:VIn:"`, an unknown capital or digit a signal | psmisc 23.7 `killall.c` |
//! | `iptables`, `ip6tables` | `getopt_long`, `"-:A:C:D:E:F::I:L::M:N:P:R:S::VX::Z::c:d:i:j:o:p:s:t:vW::46fg:h::m:nw::x"`: in order; `xs_has_arg` | iptables 1.8.11 `xshared.[ch]`, `xtables.c` |
//! | `nft` | `getopt_long` with `+`: the first operand ends the options; the operands are one command line | nftables 1.0.6, 1.1.3 `main.c` |
//! | `firewall-cmd` | Python's argparse (prefixes, `=value`) | firewalld 2.3.1 `firewall-cmd` |
//!
//! An option a table does not hold (another version's, an iptables
//! extension's not listed) makes the argv not understood: what is judged
//! on it then is the reader's over-approximation, which errs toward a
//! detection.

use std::path::Path;

use crate::posture::script_args::{read_tool, Dash, Getopt, Long, Opt, Parsed, Permute, Table};

/// The fields every system tool's table shares.
const GETOPT: Table = Table {
    short: &[],
    long: &[],
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
    dash: Dash::Operand,
    getopt: Getopt::Prefix,
    permute: Permute::Gnu,
    aliases: &[],
    signals: false,
    invert: false,
    extensions: &[],
    command_text: false,
};

/// systemd's `systemctl` (249–262: the options of each, `--kill-who`
/// before 252, `-v`, `--kill-subgroup`, `--kernel-cmdline` from 262).
const SYSTEMCTL: Table = Table {
    short: &[("hialqfTrv", Opt::Flag), ("CtpPsHMno", Opt::Arg)],
    long: &[
        ("help", Long::Flag),
        ("version", Long::Flag),
        ("type", Long::Arg),
        ("property", Long::Arg),
        ("all", Long::Flag),
        ("reverse", Long::Flag),
        ("after", Long::Flag),
        ("before", Long::Flag),
        ("show-types", Long::Flag),
        ("failed", Long::Flag),
        ("full", Long::Flag),
        ("job-mode", Long::Arg),
        ("fail", Long::Flag),
        ("irreversible", Long::Flag),
        ("ignore-dependencies", Long::Flag),
        ("ignore-inhibitors", Long::Flag),
        ("check-inhibitors", Long::Arg),
        ("value", Long::Flag),
        ("user", Long::Flag),
        ("system", Long::Flag),
        ("global", Long::Flag),
        ("capsule", Long::Arg),
        ("wait", Long::Flag),
        ("no-block", Long::Flag),
        ("legend", Long::Arg),
        ("no-legend", Long::Flag),
        ("no-pager", Long::Flag),
        ("no-wall", Long::Flag),
        ("dry-run", Long::Flag),
        ("quiet", Long::Flag),
        ("verbose", Long::Flag),
        ("no-warn", Long::Flag),
        ("root", Long::Arg),
        ("image", Long::Arg),
        ("image-policy", Long::Arg),
        ("force", Long::Flag),
        ("no-reload", Long::Flag),
        ("kill-whom", Long::Arg),
        ("kill-who", Long::Arg),
        ("kill-value", Long::Arg),
        ("kill-subgroup", Long::Arg),
        ("signal", Long::Arg),
        ("no-ask-password", Long::Flag),
        ("host", Long::Arg),
        ("machine", Long::Arg),
        ("runtime", Long::Flag),
        ("lines", Long::Arg),
        ("output", Long::Arg),
        ("plain", Long::Flag),
        ("state", Long::Arg),
        ("recursive", Long::Flag),
        ("with-dependencies", Long::Flag),
        ("preset-mode", Long::Arg),
        ("firmware-setup", Long::Flag),
        ("boot-loader-menu", Long::Arg),
        ("boot-loader-entry", Long::Arg),
        ("now", Long::Flag),
        ("message", Long::Arg),
        ("show-transaction", Long::Flag),
        ("what", Long::Arg),
        ("reboot-argument", Long::Arg),
        ("kernel-cmdline", Long::Arg),
        ("kernel-cmdline-reuse", Long::Flag),
        ("timestamp", Long::Arg),
        ("read-only", Long::Flag),
        ("mkdir", Long::Flag),
        ("marked", Long::Flag),
        ("drop-in", Long::Arg),
        ("when", Long::Arg),
        ("stdin", Long::Flag),
    ],
    aliases: &[
        ("help", 'h'),
        ("type", 't'),
        ("property", 'p'),
        ("all", 'a'),
        ("full", 'l'),
        ("ignore-inhibitors", 'i'),
        ("quiet", 'q'),
        ("verbose", 'v'),
        ("force", 'f'),
        ("signal", 's'),
        ("host", 'H'),
        ("machine", 'M'),
        ("lines", 'n'),
        ("output", 'o'),
        ("recursive", 'r'),
        ("show-transaction", 'T'),
        ("capsule", 'C'),
    ],
    ..GETOPT
};

/// procps' `kill` (`/usr/bin/kill` on Debian and Ubuntu).
const KILL: Table = Table {
    short: &[
        ("LhV", Opt::Flag),
        ("l", Opt::OptionalNext),
        ("sq", Opt::Arg),
    ],
    long: &[
        ("list", Long::Optional),
        ("table", Long::Flag),
        ("signal", Long::Arg),
        ("help", Long::Flag),
        ("version", Long::Flag),
        ("queue", Long::Arg),
    ],
    aliases: &[
        ("list", 'l'),
        ("table", 'L'),
        ("signal", 's'),
        ("help", 'h'),
        ("version", 'V'),
        ("queue", 'q'),
    ],
    signals: true,
    ..GETOPT
};

/// procps' `pkill` (its own letters and the ones it shares with pgrep; a
/// signal by `--signal` or `-SIGNAL`).
const PKILL: Table = Table {
    short: &[("eLcfinoxAH?Vh", Opt::Flag), ("qFPOgsuUGtr", Opt::Arg)],
    long: &[
        ("signal", Long::Arg),
        ("ignore-ancestors", Long::Flag),
        ("require-handler", Long::Flag),
        ("count", Long::Flag),
        ("cgroup", Long::Arg),
        ("delimiter", Long::Arg),
        ("list-name", Long::Flag),
        ("list-full", Long::Flag),
        ("full", Long::Flag),
        ("pgroup", Long::Arg),
        ("group", Long::Arg),
        ("ignore-case", Long::Flag),
        ("newest", Long::Flag),
        ("oldest", Long::Flag),
        ("older", Long::Arg),
        ("parent", Long::Arg),
        ("session", Long::Arg),
        ("terminal", Long::Arg),
        ("euid", Long::Arg),
        ("uid", Long::Arg),
        ("inverse", Long::Flag),
        ("lightweight", Long::Flag),
        ("exact", Long::Flag),
        ("pidfile", Long::Arg),
        ("logpidfile", Long::Flag),
        ("echo", Long::Flag),
        ("ns", Long::Arg),
        ("nslist", Long::Arg),
        ("queue", Long::Arg),
        ("runstates", Long::Arg),
        ("env", Long::Arg),
        ("help", Long::Flag),
        ("version", Long::Flag),
    ],
    aliases: &[
        ("ignore-ancestors", 'A'),
        ("require-handler", 'H'),
        ("count", 'c'),
        ("full", 'f'),
        ("pgroup", 'g'),
        ("group", 'G'),
        ("ignore-case", 'i'),
        ("newest", 'n'),
        ("oldest", 'o'),
        ("older", 'O'),
        ("parent", 'P'),
        ("session", 's'),
        ("terminal", 't'),
        ("euid", 'u'),
        ("uid", 'U'),
        ("exact", 'x'),
        ("pidfile", 'F'),
        ("logpidfile", 'L'),
        ("echo", 'e'),
        ("queue", 'q'),
        ("runstates", 'r'),
        ("help", 'h'),
        ("version", 'V'),
    ],
    signals: true,
    ..GETOPT
};

/// psmisc's `killall` (`getopt_long_only`: `-signal KILL`, `-sig KILL`).
const KILLALL: Table = Table {
    short: &[("egilqrvwVI", Opt::Flag), ("yosuZn", Opt::Arg)],
    long: &[
        ("exact", Long::Flag),
        ("ignore-case", Long::Flag),
        ("process-group", Long::Flag),
        ("younger-than", Long::Arg),
        ("older-than", Long::Arg),
        ("interactive", Long::Flag),
        ("list-signals", Long::Flag),
        ("quiet", Long::Flag),
        ("regexp", Long::Flag),
        ("signal", Long::Arg),
        ("user", Long::Arg),
        ("verbose", Long::Flag),
        ("wait", Long::Flag),
        ("ns", Long::Arg),
        ("context", Long::Arg),
        ("version", Long::Flag),
    ],
    aliases: &[
        ("exact", 'e'),
        ("ignore-case", 'I'),
        ("process-group", 'g'),
        ("younger-than", 'y'),
        ("older-than", 'o'),
        ("interactive", 'i'),
        ("list-signals", 'l'),
        ("quiet", 'q'),
        ("regexp", 'r'),
        ("signal", 's'),
        ("user", 'u'),
        ("verbose", 'v'),
        ("wait", 'w'),
        ("ns", 'n'),
        ("context", 'Z'),
        ("version", 'V'),
    ],
    getopt: Getopt::PrefixOneHyphen,
    signals: true,
    ..GETOPT
};

/// iptables and ip6tables (legacy and nft): the commands, the rule's
/// parameters, and the options of the extensions in common use (found by
/// their full name only: iptables merges them when `-m`, `-j` or `-p`
/// loads one). `-F`, `-X`, `-L`, `-S`, `-Z`, `-w`, `-W`, `-h` take their
/// argument attached, else the next one unless it starts with `-` or `!`;
/// `-P` and `-E` two (`xs_has_arg`).
const IPTABLES: Table = Table {
    short: &[
        ("Vv46fnx", Opt::Flag),
        ("ACDIMNRcdijopstgm", Opt::Arg),
        ("FXLSZwWh", Opt::OptionalNext),
        ("PE", Opt::Arg2),
    ],
    long: &[
        ("append", Long::Arg),
        ("delete", Long::Arg),
        ("check", Long::Arg),
        ("insert", Long::Arg),
        ("replace", Long::Arg),
        ("list", Long::OptionalNext),
        ("list-rules", Long::OptionalNext),
        ("flush", Long::OptionalNext),
        ("zero", Long::OptionalNext),
        ("new-chain", Long::Arg),
        ("delete-chain", Long::OptionalNext),
        ("rename-chain", Long::Arg2),
        ("policy", Long::Arg2),
        ("source", Long::Arg),
        ("destination", Long::Arg),
        ("src", Long::Arg),
        ("dst", Long::Arg),
        ("protocol", Long::Arg),
        ("in-interface", Long::Arg),
        ("jump", Long::Arg),
        ("table", Long::Arg),
        ("match", Long::Arg),
        ("numeric", Long::Flag),
        ("out-interface", Long::Arg),
        ("verbose", Long::Flag),
        ("wait", Long::OptionalNext),
        ("wait-interval", Long::OptionalNext),
        ("exact", Long::Flag),
        ("fragments", Long::Flag),
        ("version", Long::Flag),
        ("help", Long::OptionalNext),
        ("line-numbers", Long::Flag),
        ("modprobe", Long::Arg),
        ("set-counters", Long::Arg),
        ("goto", Long::Arg),
        ("ipv4", Long::Flag),
        ("ipv6", Long::Flag),
    ],
    aliases: &[
        ("append", 'A'),
        ("delete", 'D'),
        ("check", 'C'),
        ("insert", 'I'),
        ("replace", 'R'),
        ("list", 'L'),
        ("list-rules", 'S'),
        ("flush", 'F'),
        ("zero", 'Z'),
        ("new-chain", 'N'),
        ("delete-chain", 'X'),
        ("rename-chain", 'E'),
        ("policy", 'P'),
        ("source", 's'),
        ("destination", 'd'),
        ("src", 's'),
        ("dst", 'd'),
        ("protocol", 'p'),
        ("in-interface", 'i'),
        ("jump", 'j'),
        ("table", 't'),
        ("match", 'm'),
        ("numeric", 'n'),
        ("out-interface", 'o'),
        ("verbose", 'v'),
        ("wait", 'w'),
        ("wait-interval", 'W'),
        ("exact", 'x'),
        ("fragments", 'f'),
        ("version", 'V'),
        ("help", 'h'),
        ("modprobe", 'M'),
        ("set-counters", 'c'),
        ("goto", 'g'),
        ("ipv4", '4'),
        ("ipv6", '6'),
    ],
    // iptables-extensions(8): the matches and targets of a host's, a
    // container runtime's and an orchestrator's rules
    extensions: &[
        ("sport", Long::Arg),
        ("source-port", Long::Arg),
        ("dport", Long::Arg),
        ("destination-port", Long::Arg),
        ("sports", Long::Arg),
        ("source-ports", Long::Arg),
        ("dports", Long::Arg),
        ("destination-ports", Long::Arg),
        ("ports", Long::Arg),
        ("tcp-flags", Long::Arg2),
        ("syn", Long::Flag),
        ("tcp-option", Long::Arg),
        ("icmp-type", Long::Arg),
        ("icmpv6-type", Long::Arg),
        ("state", Long::Arg),
        ("ctstate", Long::Arg),
        ("ctproto", Long::Arg),
        ("ctstatus", Long::Arg),
        ("ctdir", Long::Arg),
        ("ctorigsrc", Long::Arg),
        ("ctorigdst", Long::Arg),
        ("ctreplsrc", Long::Arg),
        ("ctrepldst", Long::Arg),
        ("ctorigsrcport", Long::Arg),
        ("ctorigdstport", Long::Arg),
        ("comment", Long::Arg),
        ("log-level", Long::Arg),
        ("log-prefix", Long::Arg),
        ("log-tcp-sequence", Long::Flag),
        ("log-tcp-options", Long::Flag),
        ("log-ip-options", Long::Flag),
        ("log-uid", Long::Flag),
        ("nflog-group", Long::Arg),
        ("nflog-prefix", Long::Arg),
        ("nflog-range", Long::Arg),
        ("nflog-size", Long::Arg),
        ("nflog-threshold", Long::Arg),
        ("reject-with", Long::Arg),
        ("to-destination", Long::Arg),
        ("to-source", Long::Arg),
        ("to-ports", Long::Arg),
        ("random", Long::Flag),
        ("random-fully", Long::Flag),
        ("persistent", Long::Flag),
        ("set-mark", Long::Arg),
        ("set-xmark", Long::Arg),
        ("and-mark", Long::Arg),
        ("or-mark", Long::Arg),
        ("xor-mark", Long::Arg),
        ("save-mark", Long::Flag),
        ("restore-mark", Long::Flag),
        ("nfmask", Long::Arg),
        ("ctmask", Long::Arg),
        ("mark", Long::Arg),
        ("limit", Long::Arg),
        ("limit-burst", Long::Arg),
        ("uid-owner", Long::Arg),
        ("gid-owner", Long::Arg),
        ("socket-exists", Long::Flag),
        ("suppl-groups", Long::Flag),
        ("match-set", Long::Arg2),
        ("return-nomatch", Long::Flag),
        ("add-set", Long::Arg2),
        ("del-set", Long::Arg2),
        ("exist", Long::Flag),
        ("timeout", Long::Arg),
        ("name", Long::Arg),
        ("set", Long::Flag),
        ("rsource", Long::Flag),
        ("rdest", Long::Flag),
        ("rcheck", Long::Flag),
        ("update", Long::Flag),
        ("remove", Long::Flag),
        ("seconds", Long::Arg),
        ("hitcount", Long::Arg),
        ("rttl", Long::Flag),
        ("reap", Long::Flag),
        ("mask", Long::Arg),
        ("src-type", Long::Arg),
        ("dst-type", Long::Arg),
        ("limit-iface-in", Long::Flag),
        ("limit-iface-out", Long::Flag),
        ("src-range", Long::Arg),
        ("dst-range", Long::Arg),
        ("physdev-in", Long::Arg),
        ("physdev-out", Long::Arg),
        ("physdev-is-in", Long::Flag),
        ("physdev-is-out", Long::Flag),
        ("physdev-is-bridged", Long::Flag),
        ("set-mss", Long::Arg),
        ("clamp-mss-to-pmtu", Long::Flag),
        ("queue-num", Long::Arg),
        ("queue-balance", Long::Arg),
        ("queue-bypass", Long::Flag),
        ("connlimit-above", Long::Arg),
        ("connlimit-upto", Long::Arg),
        ("connlimit-mask", Long::Arg),
        ("connlimit-saddr", Long::Flag),
        ("connlimit-daddr", Long::Flag),
        ("hashlimit-upto", Long::Arg),
        ("hashlimit-above", Long::Arg),
        ("hashlimit-burst", Long::Arg),
        ("hashlimit-mode", Long::Arg),
        ("hashlimit-name", Long::Arg),
        ("hashlimit-htable-expire", Long::Arg),
        ("mac-source", Long::Arg),
        ("pkt-type", Long::Arg),
        ("length", Long::Arg),
        ("ttl-eq", Long::Arg),
        ("ttl-gt", Long::Arg),
        ("ttl-lt", Long::Arg),
        ("dscp", Long::Arg),
        ("dscp-class", Long::Arg),
        ("set-dscp", Long::Arg),
        ("set-dscp-class", Long::Arg),
        ("notrack", Long::Flag),
        ("zone", Long::Arg),
        ("helper", Long::Arg),
        ("dir", Long::Arg),
        ("pol", Long::Arg),
        ("strict", Long::Flag),
        ("next", Long::Flag),
        ("reqid", Long::Arg),
        ("spi", Long::Arg),
        ("proto", Long::Arg),
        ("mode", Long::Arg),
        ("tunnel-src", Long::Arg),
        ("tunnel-dst", Long::Arg),
        ("checksum-fill", Long::Flag),
        ("probability", Long::Arg),
        ("every", Long::Arg),
        ("packet", Long::Arg),
        ("algo", Long::Arg),
        ("string", Long::Arg),
        ("hex-string", Long::Arg),
        ("from", Long::Arg),
        ("to", Long::Arg),
        ("icase", Long::Flag),
        ("on-port", Long::Arg),
        ("on-ip", Long::Arg),
        ("tproxy-mark", Long::Arg),
        ("transparent", Long::Flag),
        ("nowildcard", Long::Flag),
        ("restore-skmark", Long::Flag),
        ("u32", Long::Arg),
        ("bytecode", Long::Arg),
        ("path", Long::Arg),
        ("cgroup", Long::Arg),
        ("src-group", Long::Arg),
        ("dst-group", Long::Arg),
        ("loose", Long::Flag),
        ("validmark", Long::Flag),
        ("accept-local", Long::Flag),
        ("invert", Long::Flag),
        ("type", Long::Arg),
    ],
    permute: Permute::Always,
    invert: true,
    ..GETOPT
};

/// nftables' `nft`.
const NFT: Table = Table {
    short: &[("hvVcijnsNSaeuypTto", Opt::Flag), ("fDId", Opt::Arg)],
    long: &[
        ("help", Long::Flag),
        ("version", Long::Flag),
        ("check", Long::Flag),
        ("file", Long::Arg),
        ("define", Long::Arg),
        ("interactive", Long::Flag),
        ("includepath", Long::Arg),
        ("json", Long::Flag),
        ("numeric", Long::Flag),
        ("stateless", Long::Flag),
        ("reversedns", Long::Flag),
        ("service", Long::Flag),
        ("debug", Long::Arg),
        ("handle", Long::Flag),
        ("echo", Long::Flag),
        ("guid", Long::Flag),
        ("numeric-priority", Long::Flag),
        ("numeric-protocol", Long::Flag),
        ("numeric-time", Long::Flag),
        ("terse", Long::Flag),
        ("optimize", Long::Flag),
    ],
    aliases: &[
        ("help", 'h'),
        ("version", 'v'),
        ("check", 'c'),
        ("file", 'f'),
        ("define", 'D'),
        ("interactive", 'i'),
        ("includepath", 'I'),
        ("json", 'j'),
        ("numeric", 'n'),
        ("stateless", 's'),
        ("reversedns", 'N'),
        ("service", 'S'),
        ("debug", 'd'),
        ("handle", 'a'),
        ("echo", 'e'),
        ("guid", 'u'),
        ("numeric-priority", 'y'),
        ("numeric-protocol", 'p'),
        ("numeric-time", 'T'),
        ("terse", 't'),
        ("optimize", 'o'),
    ],
    permute: Permute::No,
    command_text: true,
    ..GETOPT
};

/// firewalld's `firewall-cmd`: every option of its argparse parser (so that
/// a prefix is found as argparse finds it); the direct interface's
/// several-argument options are not read.
const FIREWALL_CMD: Table = Table {
    short: &[("vqhV", Opt::Flag)],
    long: &[
        ("add-chain", Long::Unread),
        ("add-destination", Long::Arg),
        ("add-egress-zone", Long::Arg),
        ("add-entries-from-file", Long::Arg),
        ("add-entry", Long::Arg),
        ("add-forward", Long::Flag),
        ("add-forward-port", Long::Arg),
        ("add-helper", Long::Arg),
        ("add-icmp-block", Long::Arg),
        ("add-icmp-block-inversion", Long::Flag),
        ("add-include", Long::Arg),
        ("add-ingress-zone", Long::Arg),
        ("add-interface", Long::Arg),
        ("add-lockdown-whitelist-command", Long::Arg),
        ("add-lockdown-whitelist-context", Long::Arg),
        ("add-lockdown-whitelist-uid", Long::Arg),
        ("add-lockdown-whitelist-user", Long::Arg),
        ("add-masquerade", Long::Flag),
        ("add-module", Long::Arg),
        ("add-option", Long::Arg),
        ("add-passthrough", Long::Unread),
        ("add-port", Long::Arg),
        ("add-protocol", Long::Arg),
        ("add-rich-rule", Long::Arg),
        ("add-rule", Long::Unread),
        ("add-service", Long::Arg),
        ("add-source", Long::Arg),
        ("add-source-port", Long::Arg),
        ("change-interface", Long::Arg),
        ("change-source", Long::Arg),
        ("change-zone", Long::Arg),
        ("check-config", Long::Flag),
        ("complete-reload", Long::Flag),
        ("delete-helper", Long::Arg),
        ("delete-icmptype", Long::Arg),
        ("delete-ipset", Long::Arg),
        ("delete-policy", Long::Arg),
        ("delete-service", Long::Arg),
        ("delete-zone", Long::Arg),
        ("direct", Long::Flag),
        ("family", Long::Arg),
        ("get-active-policies", Long::Flag),
        ("get-active-zones", Long::Flag),
        ("get-all-chains", Long::Flag),
        ("get-all-passthroughs", Long::Flag),
        ("get-all-rules", Long::Flag),
        ("get-automatic-helpers", Long::Flag),
        ("get-chains", Long::Unread),
        ("get-default-zone", Long::Flag),
        ("get-description", Long::Flag),
        ("get-destination", Long::Flag),
        ("get-destinations", Long::Flag),
        ("get-egress-priority", Long::Flag),
        ("get-entries", Long::Flag),
        ("get-family", Long::Flag),
        ("get-helpers", Long::Flag),
        ("get-icmptypes", Long::Flag),
        ("get-includes", Long::Flag),
        ("get-ingress-priority", Long::Flag),
        ("get-ipset-types", Long::Flag),
        ("get-ipsets", Long::Flag),
        ("get-log-denied", Long::Flag),
        ("get-module", Long::Flag),
        ("get-modules", Long::Flag),
        ("get-options", Long::Flag),
        ("get-passthroughs", Long::Arg),
        ("get-policies", Long::Flag),
        ("get-ports", Long::Flag),
        ("get-priority", Long::Flag),
        ("get-protocols", Long::Flag),
        ("get-rules", Long::Unread),
        ("get-service-helpers", Long::Flag),
        ("get-services", Long::Flag),
        ("get-short", Long::Flag),
        ("get-source-ports", Long::Flag),
        ("get-target", Long::Flag),
        ("get-zone-of-interface", Long::Arg),
        ("get-zone-of-source", Long::Arg),
        ("get-zones", Long::Flag),
        ("help", Long::Flag),
        ("helper", Long::Arg),
        ("icmptype", Long::Arg),
        ("info-helper", Long::Arg),
        ("info-icmptype", Long::Arg),
        ("info-ipset", Long::Arg),
        ("info-policy", Long::Arg),
        ("info-service", Long::Arg),
        ("info-zone", Long::Arg),
        ("ipset", Long::Arg),
        ("list-all", Long::Flag),
        ("list-all-policies", Long::Flag),
        ("list-all-zones", Long::Flag),
        ("list-egress-zones", Long::Flag),
        ("list-forward-ports", Long::Flag),
        ("list-icmp-blocks", Long::Flag),
        ("list-ingress-zones", Long::Flag),
        ("list-interfaces", Long::Flag),
        ("list-lockdown-whitelist-commands", Long::Flag),
        ("list-lockdown-whitelist-contexts", Long::Flag),
        ("list-lockdown-whitelist-uids", Long::Flag),
        ("list-lockdown-whitelist-users", Long::Flag),
        ("list-ports", Long::Flag),
        ("list-protocols", Long::Flag),
        ("list-rich-rules", Long::Flag),
        ("list-services", Long::Flag),
        ("list-source-ports", Long::Flag),
        ("list-sources", Long::Flag),
        ("load-helper-defaults", Long::Arg),
        ("load-icmptype-defaults", Long::Arg),
        ("load-ipset-defaults", Long::Arg),
        ("load-policy-defaults", Long::Arg),
        ("load-service-defaults", Long::Arg),
        ("load-zone-defaults", Long::Arg),
        ("lockdown-off", Long::Flag),
        ("lockdown-on", Long::Flag),
        ("module", Long::Arg),
        ("name", Long::Arg),
        ("new-helper", Long::Arg),
        ("new-helper-from-file", Long::Arg),
        ("new-icmptype", Long::Arg),
        ("new-icmptype-from-file", Long::Arg),
        ("new-ipset", Long::Arg),
        ("new-ipset-from-file", Long::Arg),
        ("new-policy", Long::Arg),
        ("new-policy-from-file", Long::Arg),
        ("new-service", Long::Arg),
        ("new-service-from-file", Long::Arg),
        ("new-zone", Long::Arg),
        ("new-zone-from-file", Long::Arg),
        ("option", Long::Arg),
        ("panic-off", Long::Flag),
        ("panic-on", Long::Flag),
        ("passthrough", Long::Unread),
        ("path-helper", Long::Arg),
        ("path-icmptype", Long::Arg),
        ("path-ipset", Long::Arg),
        ("path-policy", Long::Arg),
        ("path-service", Long::Arg),
        ("path-zone", Long::Arg),
        ("permanent", Long::Flag),
        ("policy", Long::Arg),
        ("query-chain", Long::Unread),
        ("query-destination", Long::Arg),
        ("query-egress-zone", Long::Arg),
        ("query-entry", Long::Arg),
        ("query-forward", Long::Flag),
        ("query-forward-port", Long::Arg),
        ("query-helper", Long::Arg),
        ("query-icmp-block", Long::Arg),
        ("query-icmp-block-inversion", Long::Flag),
        ("query-include", Long::Arg),
        ("query-ingress-zone", Long::Arg),
        ("query-interface", Long::Arg),
        ("query-lockdown", Long::Flag),
        ("query-lockdown-whitelist-command", Long::Arg),
        ("query-lockdown-whitelist-context", Long::Arg),
        ("query-lockdown-whitelist-uid", Long::Arg),
        ("query-lockdown-whitelist-user", Long::Arg),
        ("query-masquerade", Long::Flag),
        ("query-module", Long::Arg),
        ("query-option", Long::Arg),
        ("query-panic", Long::Flag),
        ("query-passthrough", Long::Unread),
        ("query-port", Long::Arg),
        ("query-protocol", Long::Arg),
        ("query-rich-rule", Long::Arg),
        ("query-rule", Long::Unread),
        ("query-service", Long::Arg),
        ("query-source", Long::Arg),
        ("query-source-port", Long::Arg),
        ("quiet", Long::Flag),
        ("reload", Long::Flag),
        ("remove-chain", Long::Unread),
        ("remove-destination", Long::Arg),
        ("remove-egress-zone", Long::Arg),
        ("remove-entries-from-file", Long::Arg),
        ("remove-entry", Long::Arg),
        ("remove-forward", Long::Flag),
        ("remove-forward-port", Long::Arg),
        ("remove-helper", Long::Arg),
        ("remove-icmp-block", Long::Arg),
        ("remove-icmp-block-inversion", Long::Flag),
        ("remove-include", Long::Arg),
        ("remove-ingress-zone", Long::Arg),
        ("remove-interface", Long::Arg),
        ("remove-lockdown-whitelist-command", Long::Arg),
        ("remove-lockdown-whitelist-context", Long::Arg),
        ("remove-lockdown-whitelist-uid", Long::Arg),
        ("remove-lockdown-whitelist-user", Long::Arg),
        ("remove-masquerade", Long::Flag),
        ("remove-module", Long::Arg),
        ("remove-option", Long::Arg),
        ("remove-passthrough", Long::Unread),
        ("remove-port", Long::Arg),
        ("remove-protocol", Long::Arg),
        ("remove-rich-rule", Long::Arg),
        ("remove-rule", Long::Unread),
        ("remove-rules", Long::Unread),
        ("remove-service", Long::Arg),
        ("remove-source", Long::Arg),
        ("remove-source-port", Long::Arg),
        ("reset-to-defaults", Long::Flag),
        ("runtime-to-permanent", Long::Flag),
        ("service", Long::Arg),
        ("set-automatic-helpers", Long::Arg),
        ("set-default-zone", Long::Arg),
        ("set-description", Long::Arg),
        ("set-destination", Long::Arg),
        ("set-egress-priority", Long::Arg),
        ("set-family", Long::Unread),
        ("set-ingress-priority", Long::Arg),
        ("set-log-denied", Long::Arg),
        ("set-module", Long::Arg),
        ("set-priority", Long::Arg),
        ("set-short", Long::Arg),
        ("set-target", Long::Arg),
        ("state", Long::Flag),
        ("timeout", Long::Arg),
        ("type", Long::Arg),
        ("verbose", Long::Flag),
        ("version", Long::Flag),
        ("zone", Long::Arg),
    ],
    aliases: &[
        ("verbose", 'v'),
        ("quiet", 'q'),
        ("help", 'h'),
        ("version", 'V'),
    ],
    permute: Permute::Always,
    ..GETOPT
};

/// The name the reader gives iptables' flush (`-F`, `--flush`, `--fl`).
pub(crate) const IPTABLES_FLUSH: &str = "F";

/// A system tool with a table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SystemTool {
    Systemctl,
    Kill,
    Pkill,
    Killall,
    /// iptables and ip6tables.
    Iptables,
    Nft,
    FirewallCmd,
}

impl SystemTool {
    /// The tool a program name is.
    pub(crate) fn named(name: &str) -> Option<Self> {
        Some(match name {
            "systemctl" => Self::Systemctl,
            "kill" => Self::Kill,
            "pkill" => Self::Pkill,
            "killall" => Self::Killall,
            "iptables" | "ip6tables" => Self::Iptables,
            "nft" => Self::Nft,
            "firewall-cmd" => Self::FirewallCmd,
            _ => return None,
        })
    }

    fn table(self) -> &'static Table {
        match self {
            Self::Systemctl => &SYSTEMCTL,
            Self::Kill => &KILL,
            Self::Pkill => &PKILL,
            Self::Killall => &KILLALL,
            Self::Iptables => &IPTABLES,
            Self::Nft => &NFT,
            Self::FirewallCmd => &FIREWALL_CMD,
        }
    }

    /// `argv[from]` on, every way the tool may read it ([`read_tool`]).
    pub(crate) fn read(self, argv: &[String], from: usize) -> Vec<Parsed<'_>> {
        read_tool(self.table(), argv, from)
    }
}

/// The xtables multi-call binaries, by basename.
const XTABLES_MULTI: &[&str] = &["xtables-nft-multi", "xtables-legacy-multi", "xtables-multi"];

/// The program names under which they run iptables or ip6tables (their
/// `subcommand` tables): their `iptables` and `ip6tables` names.
const XTABLES_MAINS: &[(&str, &str)] = &[
    ("iptables", "iptables"),
    ("iptables-nft", "iptables"),
    ("iptables-legacy", "iptables"),
    ("main4", "iptables"),
    ("ip6tables", "ip6tables"),
    ("ip6tables-nft", "ip6tables"),
    ("ip6tables-legacy", "ip6tables"),
    ("main6", "ip6tables"),
];

/// What an exec runs, by name: the names it goes by and where its own
/// arguments start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Program {
    /// Its executable's basename, its `argv[0]`'s (a tool named by its
    /// `argv[0]` gains nothing from it but a detection) and, for an
    /// iptables, `iptables` or `ip6tables` (`iptables-nft`,
    /// `iptables-legacy`, the multi-call binaries' `main4`).
    pub(crate) names: Vec<String>,
    /// The index of its first argument in `argv` (2 when a multi-call
    /// binary reads its program from `argv[1]`).
    pub(crate) args_from: usize,
}

impl Program {
    /// Lot 316: `exe` run with `argv`. The xtables multi-call binary runs
    /// the program `argv[0]` names, else the one `argv[1]` names
    /// (`subcmd_main` in iptables' `xshared.c`): `xtables-nft-multi main4
    /// -F` flushes, as `iptables-nft -F` does.
    pub(crate) fn of(exe: &Path, argv: &[String]) -> Self {
        let base = |a: &str| a.rsplit('/').next().unwrap_or(a).to_string();
        let mut names: Vec<String> = Vec::new();
        let mut push = |n: String| {
            if !names.contains(&n) {
                names.push(n);
            }
        };
        let exe_name = exe.file_name().map(|b| b.to_string_lossy().into_owned());
        if let Some(b) = &exe_name {
            push(b.clone());
        }
        let argv0 = argv.first().map(|a| base(a));
        if let Some(a) = &argv0 {
            push(a.clone());
        }
        let main = |n: &str| XTABLES_MAINS.iter().find(|(m, _)| *m == n).map(|(_, p)| *p);
        let mut args_from = 1;
        let multi = exe_name
            .iter()
            .chain(&argv0)
            .any(|n| XTABLES_MULTI.contains(&n.as_str()));
        let named_by_argv0 = argv0.as_deref().and_then(main);
        let program = match named_by_argv0 {
            Some(p) => Some(p),
            None if multi => {
                let sub = argv.get(1).map(String::as_str).and_then(main);
                if sub.is_some() {
                    args_from = 2;
                }
                sub
            }
            None => exe_name.as_deref().and_then(main),
        };
        if let Some(p) = program {
            push(p.to_string());
        }
        Self { names, args_from }
    }

    /// The program is named `name`.
    pub(crate) fn is(&self, name: &str) -> bool {
        self.names.iter().any(|n| n == name)
    }

    /// The system tool it is, of those with a table.
    pub(crate) fn tool(&self) -> Option<SystemTool> {
        self.names.iter().find_map(|n| SystemTool::named(n))
    }
}

/// Lot 316: the arguments of a switch-off command of the list (`cmd
/// iptables -P INPUT ACCEPT`), read by its program's table as an argv
/// would be: its options by name, its operands.
pub(crate) fn read_listed(tool: SystemTool, args: &[String]) -> Parsed<'_> {
    tool.read(args, 0).into_iter().next().unwrap_or_default()
}

#[cfg(test)]
mod tests;
