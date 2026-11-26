//! Lot 354 (pre-alpha, the truth of the docs): no public claim without a
//! check. The figures of the README that can be counted from the code are
//! counted here, from the code, and the README must state them as counted:
//! the rules (the catalogue's entries, those decided outside the engine and
//! the strongest test each has), the ATT&CK mapping (the generated
//! `ATTACK_COVERAGE.md`, itself checked by `cargo xtask attack-coverage
//! --check`), the deny hooks, the eBPF programs, the test functions, the
//! golden replay cases, the fuzz targets and the Kani proofs. Any other
//! "<n> rules", "<n> Kani proofs", … in the README must be one of those
//! figures too, so a stale copy elsewhere in the page fails as well.
//!
//! The same for the tables that name what the code has: GOLDEN_REPLAY.md
//! lists every golden case, and the operator's nn-admin reference names
//! every command and subcommand the binary has (read from the generated
//! help matrix, which `cargo xtask golden` checks against the binary).

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

mod support;

use support::repo_root;

fn read(rel: &str) -> String {
    let path = repo_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Every `.rs` file under `rel` (repository-relative), `target/` skipped.
fn rs_under(rel: &str) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    support::rs_files(&repo_root().join(rel), &mut out);
    out
}

/// `1234` → `1,234`, the README's way of writing a figure.
fn thousands(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// The figure written right before `noun` at each place it appears (bold
/// markers removed, thousands separators allowed): "**95** rules" → 95.
fn figures_before(text: &str, noun: &str) -> Vec<usize> {
    let text = text.replace("**", "");
    let mut out = Vec::new();
    let mut rest = text.as_str();
    while let Some(pos) = rest.find(noun) {
        let before = rest[..pos].trim_end_matches(' ');
        let digits: String = before
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_digit() || *c == ',')
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        let digits = digits.trim_start_matches(',').replace(',', "");
        if !digits.is_empty() {
            out.push(digits.parse().expect("a figure"));
        }
        rest = &rest[pos + noun.len()..];
    }
    out
}

/// How far below the count the README's floor of test functions may stay
/// (the review of #562: it was 1,000, so a floor long behind still passed).
const TESTS_MARGIN: usize = 200;

const FAMILIES: [&str; 4] = ["process", "fim", "net", "other"];

/// The ids of the rule catalogue (`crates/nn-core/src/decision/catalogue`),
/// one `RuleDoc` each.
fn catalogue_ids() -> Vec<String> {
    let mut ids = Vec::new();
    for family in FAMILIES {
        let rel = format!("crates/nn-core/src/decision/catalogue/{family}.rs");
        let text = read(&rel);
        let docs = text.matches("RuleDoc {").count();
        let mut here = 0;
        for line in text.lines() {
            if let Some(rest) = line.trim().strip_prefix("id: \"") {
                ids.push(rest.split('"').next().expect("an id").to_string());
                here += 1;
            }
        }
        assert_eq!(here, docs, "{rel}: {docs} RuleDoc entries, {here} ids");
    }
    let unique: BTreeSet<&String> = ids.iter().collect();
    assert_eq!(unique.len(), ids.len(), "a rule id twice in the catalogue");
    ids
}

/// The id prefixes of the rules decided outside the engine
/// (`rule_policy.rs`'s `OUTSIDE_ENGINE`).
fn outside_engine_prefixes() -> Vec<String> {
    let text = read("crates/nn-core/src/decision/rule_policy.rs");
    let start = text
        .find("const OUTSIDE_ENGINE: &[&str] = &[")
        .expect("rule_policy.rs: OUTSIDE_ENGINE");
    let body = &text[start..];
    let body = &body[..body.find("];").expect("the list's end")];
    let prefixes: Vec<String> = body
        .lines()
        .skip(1)
        .filter_map(|l| l.trim().strip_prefix('"'))
        .map(|l| l.split('"').next().expect("a prefix").to_string())
        .collect();
    assert!(prefixes.len() >= 3, "OUTSIDE_ENGINE: {prefixes:?}");
    prefixes
}

/// The rules' strongest test, from the generated catalogue's `Validation`
/// rows: (an end-to-end test or a lab script, unit tests only, none).
fn strongest_tests() -> (usize, usize, usize) {
    let text = read("docs/detection/RULE_CATALOGUE.md");
    let (mut e2e_or_lab, mut unit, mut none) = (0, 0, 0);
    for line in text.lines() {
        let Some(v) = line.strip_prefix("| Validation | ") else {
            continue;
        };
        let v = v.trim_end_matches(" |");
        if v.starts_with("no proof") {
            none += 1;
        } else if v.contains("e2e") || v.contains("lab") {
            e2e_or_lab += 1;
        } else if v.starts_with("unit") {
            unit += 1;
        } else {
            panic!("RULE_CATALOGUE.md: a validation status this test does not know: {line}");
        }
    }
    (e2e_or_lab, unit, none)
}

/// ATTACK_COVERAGE.md's summary: (rules mapped, rules, techniques and
/// sub-techniques, sub-techniques, tactics, Enterprise tactics).
fn attack_summary() -> [usize; 6] {
    let text = read("docs/detection/ATTACK_COVERAGE.md");
    let line = text
        .lines()
        .find(|l| l.contains(" rules the agent can record map to "))
        .expect("ATTACK_COVERAGE.md: the summary line");
    let figures: Vec<usize> = line
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .take(6)
        .map(|s| s.parse().expect("a figure"))
        .collect();
    figures.try_into().expect("six figures in the summary line")
}

/// The length of a `pub const NAME: [&str; N]` of the anti-tamper module.
fn hook_list_len(name: &str) -> usize {
    let text = read("crates/nn-linux/src/anti_tamper/mod.rs");
    let decl = format!("pub const {name}: [&str; ");
    let at = text
        .find(&decl)
        .unwrap_or_else(|| panic!("anti_tamper/mod.rs: {decl}"));
    text[at + decl.len()..]
        .split(']')
        .next()
        .and_then(|n| n.trim().parse().ok())
        .expect("the list's length")
}

/// The attributes that define a program of the eBPF object.
const PROGRAM_ATTRS: [&str; 26] = [
    "lsm",
    "lsm_cgroup",
    "tracepoint",
    "raw_tracepoint",
    "btf_tracepoint",
    "kprobe",
    "kretprobe",
    "uprobe",
    "uretprobe",
    "fentry",
    "fexit",
    "cgroup_sysctl",
    "cgroup_skb",
    "cgroup_sock",
    "cgroup_sock_addr",
    "cgroup_sockopt",
    "cgroup_device",
    "xdp",
    "classifier",
    "sock_ops",
    "sk_msg",
    "sk_skb",
    "sk_lookup",
    "socket_filter",
    "perf_event",
    "flow_dissector",
];

/// The programs of the eBPF object (`agent-ebpf/src`): one aya program
/// attribute each, and the iterators placed by
/// `#[unsafe(link_section = "iter/…")]`.
fn ebpf_programs() -> usize {
    let mut n = 0;
    for file in rs_under("agent-ebpf/src") {
        let text = fs::read_to_string(&file).expect("readable");
        for line in text.lines() {
            let l = line.trim();
            if l.starts_with("#[unsafe(link_section = \"iter/") {
                n += 1;
                continue;
            }
            let Some(attr) = l.strip_prefix("#[") else {
                continue;
            };
            let name: String = attr
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            let next = attr[name.len()..].chars().next();
            if PROGRAM_ATTRS.contains(&name.as_str()) && matches!(next, Some('(') | Some(']')) {
                n += 1;
            }
        }
    }
    n
}

/// A line that declares a function, after its attributes and comments.
fn declares_fn(line: &str) -> bool {
    let mut l = line.trim();
    for word in ["pub(crate) ", "pub ", "async ", "unsafe "] {
        l = l.strip_prefix(word).unwrap_or(l);
    }
    l = l.strip_prefix("async ").unwrap_or(l);
    l.starts_with("fn ")
}

/// The test functions of the workspace's members: `#[test]` and
/// `#[tokio::test]`, each on a function.
fn test_functions() -> usize {
    let mut n = 0;
    for member in support::members() {
        for file in rs_under(&member.dir) {
            let text = fs::read_to_string(&file).expect("readable");
            let lines: Vec<&str> = text.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                let l = line.trim();
                if l != "#[test]" && !l.starts_with("#[tokio::test") {
                    continue;
                }
                let next = lines[i + 1..]
                    .iter()
                    .map(|l| l.trim())
                    .find(|l| !l.is_empty() && !l.starts_with("#[") && !l.starts_with("//"));
                if next.is_some_and(declares_fn) {
                    n += 1;
                }
            }
        }
    }
    n
}

/// Files of `dir` with `ext`, by stem.
fn stems(dir: &str, ext: &str) -> BTreeSet<String> {
    fs::read_dir(repo_root().join(dir))
        .unwrap_or_else(|e| panic!("{dir}: {e}"))
        .map(|e| e.expect("dir entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == ext))
        .map(|p| {
            p.file_stem()
                .expect("a name")
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

/// `#[kani::proof]` functions in the members' sources.
fn kani_proofs() -> usize {
    support::members()
        .into_iter()
        .flat_map(|m| rs_under(&format!("{}/src", m.dir)))
        .map(|f| {
            fs::read_to_string(&f)
                .expect("readable")
                .lines()
                .filter(|l| l.trim() == "#[kani::proof]")
                .count()
        })
        .sum()
}

fn fuzz_targets() -> usize {
    read("fuzz/Cargo.toml")
        .lines()
        .filter(|l| l.trim() == "[[bin]]")
        .count()
}

/// What the code has, counted.
struct Counted {
    rules: usize,
    outside: usize,
    strongest: (usize, usize, usize),
    attack: [usize; 6],
    deny: usize,
    optional: usize,
    programs: usize,
    tests: usize,
    golden: usize,
    posture: usize,
    fuzz: usize,
    kani: usize,
    /// Lot 364: the sensor contract's sources, and those the sensor
    /// self-test checks by their attach alone (no harmless live event).
    sources: usize,
    attach_only: usize,
}

/// Lot 364: the sensor contract's sources (`SOURCES: [SourceContract; N]`)
/// and those whose self-test word is an attach check.
fn sources() -> (usize, usize) {
    let text = read("crates/nn-linux/src/sensors/contract.rs");
    let decl = "pub const SOURCES: [SourceContract; ";
    let at = text.find(decl).expect("contract.rs: SOURCES");
    let n = text[at + decl.len()..]
        .split(']')
        .next()
        .and_then(|n| n.trim().parse().ok())
        .expect("the sources' length");
    (n, text.matches("attach_check: true,").count())
}

fn counted() -> Counted {
    let ids = catalogue_ids();
    let prefixes = outside_engine_prefixes();
    let outside = ids
        .iter()
        .filter(|id| prefixes.iter().any(|p| id.starts_with(p.as_str())))
        .count();
    let golden = stems("agent/tests/golden/cases", "json");
    assert_eq!(
        golden,
        stems("agent/tests/golden/expected", "jsonl"),
        "every golden case has its expected file and no more"
    );
    Counted {
        rules: ids.len(),
        outside,
        strongest: strongest_tests(),
        attack: attack_summary(),
        deny: hook_list_len("DENY_HOOKS"),
        optional: hook_list_len("OPTIONAL_DENY_HOOKS"),
        programs: ebpf_programs(),
        tests: test_functions(),
        golden: golden.len(),
        posture: stems("agent/tests/golden/posture/cases", "json").len(),
        fuzz: fuzz_targets(),
        kani: kani_proofs(),
        sources: sources().0,
        attach_only: sources().1,
    }
}

/// The README's problems against the counted figures, one line each.
fn readme_problems(readme: &str, c: &Counted) -> Vec<String> {
    let mut problems = Vec::new();
    let engine = c.rules - c.outside;
    let (e2e_or_lab, unit, none) = c.strongest;
    let [mapped, of, techniques, _subs, tactics, all_tactics] = c.attack;
    if (mapped, of) != (c.rules, c.rules) {
        problems.push(format!(
            "ATTACK_COVERAGE.md maps {mapped} of {of} rules, the catalogue has {}: \
             regenerate it (cargo xtask attack-coverage)",
            c.rules
        ));
    }
    if e2e_or_lab + unit + none != c.rules {
        problems.push(format!(
            "RULE_CATALOGUE.md: {} Validation rows for {} rules: regenerate it",
            e2e_or_lab + unit + none,
            c.rules
        ));
    }
    let phrases = [
        format!(
            "**{}** rules the agent can record: {engine} in the engine, {} issued outside it",
            c.rules, c.outside
        ),
        format!(
            "Strongest test per rule: an end-to-end test or a lab script for {e2e_or_lab}, \
             unit tests only for {unit}, no proof yet for {none}"
        ),
        format!(
            "{mapped} of {of} rules mapped to {techniques} techniques and sub-techniques under \
             {tactics} of {all_tactics} Enterprise tactics"
        ),
        format!("{engine} rules · chains · posture"),
        format!("against the engine's {engine} rules"),
        format!(
            "**{}** BPF-LSM deny hooks on every supported kernel, plus up to {} optional deny \
             programs",
            c.deny, c.optional
        ),
        format!(
            "BPF-LSM deny hooks<br/>{} + up to {} optional",
            c.deny, c.optional
        ),
        format!("The eBPF object holds **{}** programs", c.programs),
        format!(
            "**{}** golden replay cases of the decision path and **{}** of the posture and COMBAT ladder",
            c.golden, c.posture
        ),
        format!("**{}** fuzz targets", c.fuzz),
        format!("**{}** Kani proofs", c.kani),
        format!("eBPF sensors · {} sources", c.sources),
        format!(
            "{} of the {} sources and checks that the other {} are still attached",
            c.sources - c.attach_only,
            c.sources,
            c.attach_only
        ),
    ];
    for p in &phrases {
        if !readme.contains(p.as_str()) {
            problems.push(format!("the README does not say, word for word: {p}"));
        }
    }
    // The test functions: a floor in hundreds ("more than **5,500**"),
    // below the count and less than TESTS_MARGIN under it — a figure that
    // grows with every change is not pinned exactly, but it is never false
    // ("more than" the count itself is false too) and never far behind.
    let floor: Vec<usize> = figures_before(readme, " test functions");
    match floor.as_slice() {
        [f] if *f < c.tests && c.tests - f < TESTS_MARGIN && f.is_multiple_of(100) => {
            if !readme.contains(&format!("more than **{}** test functions", thousands(*f))) {
                problems.push(format!(
                    "the README states {f} test functions, not as \"more than **{}** test functions\"",
                    thousands(*f)
                ));
            }
        }
        _ => problems.push(format!(
            "the README's test functions {floor:?}: write \"more than **{}** test functions\" \
             ({} counted)",
            thousands((c.tests - 1) / 100 * 100),
            c.tests
        )),
    }
    // Every other figure of the same kind is one of these.
    let kinds: [(&str, Vec<usize>); 7] = [
        (" rules", vec![c.rules, engine, 0]),
        (" BPF-LSM deny hooks", vec![c.deny]),
        (" programs", vec![c.programs]),
        (" golden replay cases", vec![c.golden]),
        (" fuzz targets", vec![c.fuzz]),
        (" Kani proofs", vec![c.kani]),
        (" sources", vec![c.sources]),
    ];
    for (noun, allowed) in kinds {
        for n in figures_before(readme, noun) {
            if !allowed.contains(&n) {
                problems.push(format!(
                    "the README says {n}{noun}; the code has {allowed:?}"
                ));
            }
        }
    }
    problems
}

#[test]
fn readme_figures_match_the_code() {
    let c = counted();
    let problems = readme_problems(&read("README.md"), &c);
    assert!(
        problems.is_empty(),
        "README.md states figures the code does not have (counted by xtask/tests/readme_figures.rs):\n  {}",
        problems.join("\n  ")
    );
}

/// The counters see what they count: the figures of this tree, which a
/// change to the code moves together with the README (and this test).
#[test]
fn the_counters_count_this_tree() {
    let c = counted();
    assert!(
        c.rules >= 90 && c.outside >= 5,
        "rules {} outside {}",
        c.rules,
        c.outside
    );
    assert!(
        c.deny >= 20 && c.optional >= 1,
        "deny {} optional {}",
        c.deny,
        c.optional
    );
    assert!(c.programs >= 100, "programs {}", c.programs);
    assert!(c.tests >= 5_000, "tests {}", c.tests);
    assert!(
        c.golden >= 30 && c.posture >= 10,
        "golden {} {}",
        c.golden,
        c.posture
    );
    assert!(
        c.fuzz >= 10 && c.kani >= 1,
        "fuzz {} kani {}",
        c.fuzz,
        c.kani
    );
    assert!(
        c.sources >= 10 && c.attach_only >= 1 && c.attach_only < c.sources,
        "sources {} attach only {}",
        c.sources,
        c.attach_only
    );
    assert_eq!(thousands(5_498), "5,498");
    assert_eq!(thousands(95), "95");
    assert_eq!(thousands(1_234_567), "1,234,567");
    assert_eq!(
        figures_before("**95** rules, of 1,200 rules and x rules", " rules"),
        vec![95, 1200]
    );
}

/// The checker fails on a README that states another figure (the README of
/// rc2: 93 rules, 17 deny hooks, 11 Kani proofs, 29 golden cases) and on a
/// stale copy of a figure elsewhere in the page.
#[test]
fn the_checker_refuses_stale_figures() {
    let c = counted();
    let good = read("README.md");
    assert!(readme_problems(&good, &c).is_empty());
    for (from, to) in [
        (
            format!("**{}** rules the agent can record", c.rules),
            "**93** rules the agent can record".to_string(),
        ),
        (
            format!("**{}** Kani proofs", c.kani),
            "**11** Kani proofs".to_string(),
        ),
        (
            format!("**{}** golden replay cases", c.golden),
            "**29** golden replay cases".to_string(),
        ),
        (
            format!("**{}** BPF-LSM deny hooks", c.deny),
            "**17** BPF-LSM deny hooks".to_string(),
        ),
        (
            format!("{} of the {} sources", c.sources - c.attach_only, c.sources),
            format!("3 of the {} sources", c.sources),
        ),
    ] {
        assert!(good.contains(&from), "{from}");
        let bad = good.replacen(&from, &to, 1);
        assert!(!readme_problems(&bad, &c).is_empty(), "{to} accepted");
    }
    let stray = format!("{good}\nA line that says 93 rules.\n");
    assert!(
        readme_problems(&stray, &c)
            .iter()
            .any(|p| p.contains("93 rules")),
        "a stray figure accepted"
    );
    // the floor the README states, one TESTS_MARGIN (rounded up to a
    // hundred) behind it, and one at or above the count
    let floor = figures_before(&good, " test functions");
    assert_eq!(floor.len(), 1, "{floor:?}");
    let stated = format!("more than **{}** test functions", thousands(floor[0]));
    let behind = (c.tests - TESTS_MARGIN) / 100 * 100;
    let far = good.replace(
        &stated,
        &format!("more than **{}** test functions", thousands(behind)),
    );
    assert!(
        !readme_problems(&far, &c).is_empty(),
        "a floor {behind}, more than {TESTS_MARGIN} behind {}, accepted",
        c.tests
    );
    let above = c.tests.div_ceil(100) * 100;
    let false_floor = good.replace(
        &stated,
        &format!("more than **{}** test functions", thousands(above)),
    );
    assert!(
        !readme_problems(&false_floor, &c).is_empty(),
        "a floor {above} at or above the count {} accepted",
        c.tests
    );
}

/// The case names of the table under `heading` (up to the next heading of
/// the same level or above).
fn table_cases(text: &str, heading: &str) -> BTreeSet<String> {
    let start = text
        .find(heading)
        .unwrap_or_else(|| panic!("GOLDEN_REPLAY.md: {heading}"));
    let level = heading.chars().take_while(|c| *c == '#').count();
    let body = &text[start + heading.len()..];
    let end = body
        .lines()
        .scan(0usize, |at, l| {
            let here = *at;
            *at += l.len() + 1;
            Some((here, l))
        })
        .find(|(_, l)| {
            let hashes = l.chars().take_while(|c| *c == '#').count();
            hashes > 0 && hashes <= level && l[hashes..].starts_with(' ')
        })
        .map_or(body.len(), |(at, _)| at);
    body[..end]
        .lines()
        .filter_map(|l| l.strip_prefix("| `"))
        .map(|l| l.split('`').next().expect("a case").to_string())
        .collect()
}

/// GOLDEN_REPLAY.md's tables of cases name every case of the code, and only
/// those (it missed 7 of the 35 decision cases at rc2).
#[test]
fn golden_replay_lists_every_case() {
    let text = read("docs/validation/GOLDEN_REPLAY.md");
    for (heading, dir) in [
        ("## 3. The cases", "agent/tests/golden/cases"),
        ("### 6.3 The cases", "agent/tests/golden/posture/cases"),
    ] {
        let listed = table_cases(&text, heading);
        let present = stems(dir, "json");
        let missing: Vec<_> = present.difference(&listed).collect();
        let extra: Vec<_> = listed.difference(&present).collect();
        assert!(
            missing.is_empty() && extra.is_empty(),
            "GOLDEN_REPLAY.md {heading}: not listed {missing:?}; listed with no case {extra:?} ({dir})"
        );
    }
}

/// The nn-admin commands, from the generated help matrix: each
/// `$ nn-admin [<cmd> …] --help` case's `Commands:` list, `help` left out.
fn nn_admin_commands() -> BTreeSet<String> {
    let text = read("agent/tests/golden/nn-admin/expected/help.txt");
    let mut out = BTreeSet::new();
    let mut parent: Option<String> = None;
    let mut in_commands = false;
    for line in text.lines() {
        if let Some(cmd) = line.strip_prefix("$ ") {
            let words: Vec<&str> = cmd.split_whitespace().collect();
            parent = (words.first() == Some(&"nn-admin")
                && matches!(words.last(), Some(&"--help") | Some(&"-h")))
            .then(|| words[..words.len() - 1].join(" "));
            in_commands = false;
            continue;
        }
        let Some(body) = line.strip_prefix('|') else {
            continue;
        };
        if body.trim() == "Commands:" {
            in_commands = true;
            continue;
        }
        if !in_commands {
            continue;
        }
        let Some(name) = body.strip_prefix("   ") else {
            in_commands = false;
            continue;
        };
        let name = name.split_whitespace().next().unwrap_or("");
        if name.is_empty() || name.starts_with('-') {
            in_commands = false;
            continue;
        }
        if let Some(p) = &parent {
            if name != "help" {
                out.insert(format!("{p} {name}"));
            }
        }
    }
    // the top-level list is in the no-argument case
    for cmd in top_level_commands(&text) {
        out.insert(format!("nn-admin {cmd}"));
    }
    out
}

/// The commands of `nn-admin`'s own usage (its no-argument case).
fn top_level_commands(text: &str) -> Vec<String> {
    let case = text
        .split("### help.no-arguments")
        .nth(1)
        .expect("help.txt: the no-argument case");
    let list = case
        .split("| Commands:")
        .nth(1)
        .expect("its Commands: list");
    list.lines()
        .skip(1)
        .map_while(|l| l.strip_prefix("|   "))
        .filter_map(|l| l.split_whitespace().next())
        .filter(|n| *n != "help")
        .map(str::to_string)
        .collect()
}

/// Every nn-admin command and subcommand is in the operator's reference
/// (docs/operator/NN_ADMIN.md) as `nn-admin <cmd> [<sub>]`: at rc2 eight
/// had no word in any operator document.
#[test]
fn every_nn_admin_command_is_in_the_operator_reference() {
    let commands = nn_admin_commands();
    assert!(
        commands.len() >= 40 && commands.contains("nn-admin net fingerprint"),
        "the help matrix gave {commands:?}"
    );
    let reference = read("docs/operator/NN_ADMIN.md");
    // a group (`nn-admin net`) is named by its subcommands
    let leaves = commands
        .iter()
        .filter(|c| !commands.iter().any(|o| o.starts_with(&format!("{c} "))));
    let missing: Vec<&String> = leaves
        .filter(|c| !reference.contains(&format!("`{c}`")))
        .collect();
    assert!(
        missing.is_empty(),
        "docs/operator/NN_ADMIN.md does not name {missing:?}"
    );
    assert!(Path::new(&repo_root().join("docs/operator/NN_ADMIN.md")).is_file());
}

/// Lot 364: a row of a Markdown table, its cells trimmed.
fn cells(line: &str) -> Vec<String> {
    line.trim()
        .trim_matches('|')
        .split('|')
        .map(|c| c.trim().to_string())
        .collect()
}

/// `ubuntu2204` for "Ubuntu 22.04 LTS", `debian12` for "Debian 12": the
/// lab's guest name of a README distribution, if it has one.
fn guest_of(distro: &str) -> Option<String> {
    let mut words = distro.split_whitespace();
    let name = words.next()?.to_lowercase();
    let version = words.next()?.replace('.', "");
    match name.as_str() {
        "ubuntu" | "debian" => Some(format!("{name}{version}")),
        // lot 1.10: nn-lab.sh's alma9
        "almalinux" => Some(format!("alma{version}")),
        _ => None,
    }
}

/// The lab workflow's guests: (those of a pull request, those of the
/// nightly), from the matrix's two JSON lists.
fn lab_guests() -> (Vec<String>, Vec<String>) {
    let text = read(".github/workflows/lab-vm.yml");
    let line = text
        .lines()
        .find(|l| l.trim_start().starts_with("distro: ${{ fromJSON("))
        .expect("lab-vm.yml: the distro matrix");
    let lists: Vec<Vec<String>> = line
        .split('[')
        .skip(1)
        .map(|l| {
            l.split(']')
                .next()
                .unwrap()
                .split(',')
                .map(|g| g.trim().trim_matches('"').to_string())
                .collect()
        })
        .collect();
    assert_eq!(lists.len(), 2, "lab-vm.yml: two guest lists: {line}");
    (lists[0].clone(), lists[1].clone())
}

/// The README's kernel table: its distributions, their kernels and their
/// gates are the lab's (the nightly's and the pull requests' guests, the
/// verified matrix's kernels), and its deny-hook figures are the code's:
/// the mandatory hooks plus the optional ones, the two ACL hooks only
/// from 6.2 (or on RHEL 9's 5.14, which backports them).
#[test]
fn the_readme_kernel_table_is_the_lab_s_and_the_code_s() {
    let readme = read("README.md");
    let c = counted();
    let acl = read("crates/nn-linux/src/anti_tamper/mod.rs")
        .split("pub const OPTIONAL_DENY_HOOKS")
        .nth(1)
        .and_then(|t| t.split("];").next())
        .map(|t| t.matches("_acl\"").count())
        .expect("OPTIONAL_DENY_HOOKS");
    assert_eq!(acl, 2, "the optional ACL hooks");
    let (on_prs, nightly) = lab_guests();
    let compat = read("docs/operator/KERNEL_COMPATIBILITY.md");
    let rows: Vec<Vec<String>> = readme
        .lines()
        .skip_while(|l| !l.starts_with("| Distribution | Kernel | systemd |"))
        .skip(2)
        .take_while(|l| l.starts_with('|'))
        .map(cells)
        .collect();
    assert!(rows.len() >= 5, "the README's kernel table: {rows:?}");
    let mut nightly_rows = Vec::new();
    for r in &rows {
        let (distro, kernel, gate, hooks) = (&r[0], &r[1], &r[4], &r[5]);
        let Some(guest) = guest_of(distro) else {
            assert!(
                !gate.contains("every night"),
                "{distro}: not a lab guest, yet in the nightly gate"
            );
            continue;
        };
        assert_eq!(
            gate.contains("every night"),
            nightly.contains(&guest),
            "{distro}: README gate {gate:?}, the nightly's guests {nightly:?}"
        );
        assert_eq!(
            gate.contains("on PRs"),
            on_prs.contains(&guest),
            "{distro}: README gate {gate:?}, a pull request's guests {on_prs:?}"
        );
        if nightly.contains(&guest) {
            nightly_rows.push(guest.clone());
        }
        let short = distro.trim_end_matches(" LTS");
        // "5.14 (el9)": the version, without the vendor's note
        let version = kernel.split_whitespace().next().unwrap_or(kernel);
        assert!(
            compat.lines().any(|l| l.starts_with(&format!("| {short}"))
                && cells(l).get(1).is_some_and(|k| k.starts_with(version))),
            "{distro} {kernel}: not a row of KERNEL_COMPATIBILITY.md's verified matrix"
        );
        let (major, minor) = kernel.split_once('.').expect("a kernel x.y");
        // "5.14 (el9)": a vendor kernel's suffix after the minor
        let minor: String = minor.chars().take_while(char::is_ascii_digit).collect();
        // RHEL 9's 5.14 backports the ACL hooks: 28 of 28 deny hooks
        // attached on 5.14.0-741 el9_9 (lot 1.10's round)
        let from_6_2 = (major.parse::<u32>().unwrap(), minor.parse::<u32>().unwrap()) >= (6, 2)
            || kernel.ends_with("(el9)");
        let want = c.deny + c.optional - if from_6_2 { 0 } else { acl };
        assert_eq!(
            hooks.parse::<usize>().ok(),
            Some(want),
            "{distro} {kernel}: README {hooks} deny hooks, the code {want}"
        );
    }
    nightly_rows.sort();
    let mut want = nightly.clone();
    want.sort();
    assert_eq!(nightly_rows, want, "every nightly guest is a README row");
    let sentence = format!(
        "{} on 6.8, 6.12 and 7.0, {} on 5.15 and 6.1 (the ACL hooks start in 6.2)",
        c.deny + c.optional,
        c.deny + c.optional - acl
    );
    assert!(readme.contains(&sentence), "the README says: {sentence}");
}

/// The capability levels the README states are the program's table
/// (`CAPABILITY_PROGRAM.md`, its Level column), and its sentence counts
/// them.
#[test]
fn the_readme_capability_levels_are_the_program_s() {
    let readme = read("README.md");
    let program = read("docs/roadmap/CAPABILITY_PROGRAM.md");
    let mut level_of = std::collections::BTreeMap::new();
    for l in program.lines().filter(|l| l.starts_with("| C")) {
        let c = cells(l);
        // "2", "2 (lot B2, 11/11)", "0: absent by design, …"
        if c.len() >= 3 && c[0].len() == 3 {
            if let Some(n) = c[2].chars().next().and_then(|d| d.to_digit(10)) {
                level_of.entry(c[0].clone()).or_insert(n);
            }
        }
    }
    assert_eq!(
        level_of.len(),
        30,
        "the program's 30 capabilities: {level_of:?}"
    );
    let words = [
        "no", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
        "eleven", "twelve", "thirteen", "fourteen", "fifteen",
    ];
    let mut counts = [0usize; 4];
    for level in 0..=3u32 {
        let row = readme
            .lines()
            .find(|l| l.starts_with(&format!("| **{level}** | C")));
        let ids: BTreeSet<String> = row
            .map(|r| {
                r.split(['|', '·'])
                    .filter_map(|p| {
                        let p = p.trim();
                        (p.len() >= 3
                            && p.starts_with('C')
                            && p[1..3].chars().all(|c| c.is_ascii_digit()))
                        .then(|| p[..3].to_string())
                    })
                    .collect()
            })
            .unwrap_or_default();
        let want: BTreeSet<String> = level_of
            .iter()
            .filter(|(_, l)| **l == level)
            .map(|(id, _)| id.clone())
            .collect();
        assert_eq!(
            ids, want,
            "README level {level}: the program's table says otherwise"
        );
        counts[level as usize] = ids.len();
    }
    let cap = |s: &str| {
        let mut ch = s.chars();
        ch.next()
            .map(|f| f.to_uppercase().collect::<String>() + ch.as_str())
            .unwrap_or_default()
    };
    let at3 = if counts[3] == 0 {
        "**No capability is at level 3.**".to_string()
    } else {
        format!("**{} at level 3.**", cap(words[counts[3]]))
    };
    let sentence = format!(
        "{at3} {} are at 2, {} at 1 and {} at 0.",
        cap(words[counts[2]]),
        words[counts[1]],
        words[counts[0]]
    );
    assert!(readme.contains(&sentence), "the README says: {sentence}");
}

/// The figures (two characters or more: `3,699`, `6.5`, `41`) of a text,
/// links left out.
fn figures(text: &str) -> BTreeSet<String> {
    let mut plain = String::new();
    let mut rest = text;
    while let Some(i) = rest.find("](") {
        plain.push_str(&rest[..i]);
        rest = rest[i..].split_once(')').map_or("", |(_, r)| r);
    }
    plain.push_str(rest);
    let mut out = BTreeSet::new();
    let mut cur = String::new();
    for ch in plain.chars().chain(std::iter::once(' ')) {
        if ch.is_ascii_digit() || (!cur.is_empty() && (ch == ',' || ch == '.')) {
            cur.push(ch);
        } else {
            let f = cur.trim_end_matches([',', '.']).to_string();
            if f.len() >= 2 {
                out.insert(f);
            }
            cur.clear();
        }
    }
    out
}

/// Lot 364: every figure of the README's table of what is measured is in
/// the file its row names as the source, or in `CAPABILITY_PROGRAM.md`,
/// whose lot notes record each lab measurement with its lot: no figure of
/// the table comes from nowhere.
#[test]
fn the_readme_s_measured_figures_are_in_their_sources() {
    let readme = read("README.md");
    let program = figures(&read("docs/roadmap/CAPABILITY_PROGRAM.md"));
    let rows: Vec<Vec<String>> = readme
        .lines()
        .skip_while(|l| !l.starts_with("| Area | Today | Source |"))
        .skip(2)
        .take_while(|l| l.starts_with('|'))
        .map(cells)
        .collect();
    assert!(rows.len() >= 10, "the README's table of measures: {rows:?}");
    // the floor of test functions is counted from the code (above)
    let floor: Vec<String> = figures_before(&readme, " test functions")
        .into_iter()
        .map(thousands)
        .collect();
    let mut problems = Vec::new();
    for r in &rows {
        let source = r[2]
            .split("](")
            .nth(1)
            .and_then(|s| s.split([')', '#']).next())
            .unwrap_or_else(|| panic!("{}: no source link", r[0]));
        let doc = if source.starts_with("http") {
            String::new()
        } else {
            read(source)
        };
        for f in figures(&r[1]) {
            if !floor.contains(&f) && !figures(&doc).contains(&f) && !program.contains(&f) {
                problems.push(format!(
                    "{}: {f} is neither in {source} nor in CAPABILITY_PROGRAM.md",
                    r[0]
                ));
            }
        }
    }
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    assert_eq!(
        figures("lost: 3,699 before, **0** after, 6.5 s, [run 4159](x/1234) in 2026."),
        ["2026", "3,699", "4159", "6.5"]
            .map(String::from)
            .into_iter()
            .collect()
    );
}
