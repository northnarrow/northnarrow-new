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
/// attribute each, and the iterators placed by `link_section = "iter/…"`.
fn ebpf_programs() -> usize {
    let mut n = 0;
    for file in rs_under("agent-ebpf/src") {
        let text = fs::read_to_string(&file).expect("readable");
        for line in text.lines() {
            let l = line.trim();
            if l.starts_with("#[link_section = \"iter/") {
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
    let kinds: [(&str, Vec<usize>); 6] = [
        (" rules", vec![c.rules, engine, 0]),
        (" BPF-LSM deny hooks", vec![c.deny]),
        (" programs", vec![c.programs]),
        (" golden replay cases", vec![c.golden]),
        (" fuzz targets", vec![c.fuzz]),
        (" Kani proofs", vec![c.kani]),
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
