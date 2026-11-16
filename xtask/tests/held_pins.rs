//! Fix round 3 of #567 (the coordinator's decision): the agent holds a
//! descriptor of every link and program it pins — a ratchet.
//!
//! A link or a program pinned outside `antitamper-bpf/src/held.rs` (aya's
//! `FdLink::pin`, a program's `.pin(`, a raw `BPF_OBJ_PIN`) is kept by its
//! pin alone: the bpffs losing its last mount, or the pin removed or
//! hidden, detaches it while the agent runs. Every such pin goes through
//! `held::pin_link`, `held::pin_prog` or `held::pin_fd`; a map keeps its
//! own `.pin(` (the programs that use it hold it). Every pin the agent
//! removes goes through `purge_stale_pin`, which drops the descriptor held
//! for it before the unlink — the agent's own purge still detaches what it
//! retires. Each rule is shown failing on a planted violation.

mod support;

use support::{matching_brace, product_code, repo_root, strip_comments};

/// The one file that pins links and programs.
const HELD: &str = "antitamper-bpf/src/held.rs";

/// The trees that make pins: the eBPF crates name `BPF_OBJ_PIN` to judge
/// it, `common` defines it.
fn makes_pins(rel: &str) -> bool {
    !(rel.starts_with("agent-ebpf/")
        || rel.starts_with("ebpf-guard/")
        || rel.starts_with("common/"))
}

/// The `.pin(` calls of `code` that pin a link or a program: the argument
/// names one (`&link_path`, `&prog_pin`), or the receiver does (`prog`,
/// `fd_link`) — a map's pin (`&map_pin_path`, `dir.join(name)`, `&path`
/// after `map_mut(…)`) is not one.
fn link_or_prog_pins(code: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(at) = code[from..].find(".pin(") {
        let call = from + at;
        let open = call + ".pin".len();
        let arg = &code[open..open + paren_len(&code[open..])];
        let recv: String = code[..call]
            .trim_end()
            .chars()
            .rev()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        let named = |s: &str| s.contains("link") || s.contains("prog");
        if named(arg) || named(&recv) {
            out.push(format!("{recv}.pin{arg}"));
        }
        from = open;
    }
    out
}

/// The length of the parenthesised group `s` starts with.
fn paren_len(s: &str) -> usize {
    let mut depth = 0usize;
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
    }
    s.len()
}

/// Named test: no link or program pinned outside `held.rs`, no raw
/// `BPF_OBJ_PIN` there either.
#[test]
fn every_link_and_program_pin_goes_through_held() {
    let root = repo_root();
    let mut bad = Vec::new();
    let mut held_seen = false;
    for (rel, code) in product_code(&root) {
        if rel == HELD {
            held_seen = true;
            continue;
        }
        if !makes_pins(&rel) {
            continue;
        }
        for p in link_or_prog_pins(&code) {
            bad.push(format!("{rel}: {p}"));
        }
        if code.contains("BPF_OBJ_PIN") {
            bad.push(format!("{rel}: a raw BPF_OBJ_PIN"));
        }
    }
    assert!(held_seen, "{HELD} is gone");
    assert!(
        bad.is_empty(),
        "a link or program pinned by its pin alone (pin it through \
         antitamper_bpf::held::pin_link / pin_prog / pin_fd):\n{}",
        bad.join("\n")
    );
}

/// The rule, failing on planted violations and quiet on a map's pins.
#[test]
fn the_pin_rule_catches_planted_violations() {
    for planted in [
        "let pinned: PinnedLink = fd_link.pin(&link_path)?;",
        "fd_link\n        .pin(&link_path)\n        .map_err(|e| e.to_string())?;",
        "prog.pin(&prog_path).with_context(|| \"x\")?;",
        "p.pin(&prog_pin)?;",
        "link.pin(&p)?;",
    ] {
        assert_eq!(link_or_prog_pins(planted).len(), 1, "not caught: {planted}");
    }
    for map in [
        "ebpf.map_mut(PROTECTED_PIDS_MAP_NAME)\n            .ok_or_else(|| anyhow!(\"map missing\"))?\n            .pin(&map_pin_path)?;",
        "map_data(ebpf, name)?\n                    .pin(dir.join(name))\n                    .map_err(|e| format!(\"pinning {name}: {e}\"))?;",
        "Some(Map::HashMap(d)) => d\n                        .pin(&path)",
    ] {
        assert!(link_or_prog_pins(map).is_empty(), "a map's pin flagged: {map}");
    }
}

/// Named test: the agent's purge drops the descriptor held for a pin
/// before it unlinks it, and `held` pins and holds in that order.
#[test]
fn the_purge_releases_before_the_unlink() {
    let lib = strip_comments(
        &std::fs::read_to_string(repo_root().join("antitamper-bpf/src/lib.rs")).unwrap(),
    );
    let at = lib
        .find("pub fn purge_stale_pin(path: &Path) {")
        .expect("purge_stale_pin");
    let open = at + lib[at..].find('{').unwrap();
    let body = &lib[open..open + matching_brace(&lib[open..])];
    let release = body.find("held::release(path);").expect("the release");
    let unlink = body.find("std::fs::remove_file(path)").expect("the unlink");
    assert!(release < unlink, "the descriptor is dropped first");
    let held = strip_comments(&std::fs::read_to_string(repo_root().join(HELD)).unwrap());
    let pin_link = &held[held.find("pub fn pin_link(").unwrap()..];
    let (p, k) = (
        pin_link
            .find("link\n        .pin(path)")
            .expect("aya's pin"),
        pin_link
            .find("keep(path, Kind::Link, id, Holder::Own(fd));")
            .expect("ours held"),
    );
    assert!(p < k);
    assert!(pin_link.contains("keep(path, Kind::Link, id, Holder::Aya(pinned));"));
    let pin_fd = &held[held.find("pub fn pin_fd(").unwrap()..];
    assert!(pin_fd.find("obj_pin(fd, path)").unwrap() < pin_fd.find("Holder::Own(own)").unwrap());
}
