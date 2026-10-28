//! Operator documentation (external audit, Wave 3, lab PR 209: DEP-013
//! NN-AUD-385, DEP-018 NN-AUD-390). The release tarball and the packages
//! ship `docs/operator/*.md` and no other document, so every document the
//! installer, the uninstaller and the operator guides name must be one of
//! those guides, a file the release puts next to them, or a URL into the
//! source repository naming a file that exists there. Links between the
//! guides resolve, anchors included; a `§n` or a quoted section title after
//! a guide's name names a section the guide has; and no operator-facing
//! text hands out a fixed `lsm=` list (it replaces the kernel's own and can
//! switch SELinux or AppArmor off).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

/// The one URL form a shipped text uses for a file of the source
/// repository: the checker can then see that the file exists.
const REPO_BLOB: &str = "https://github.com/northnarrow/northnarrow-new/blob/main/";
const REPO: &str = "github.com/northnarrow/northnarrow-new";
/// What the release puts at its root next to `docs/operator/`
/// (`deploy/release/mk-tarball.sh`; the packages put them in
/// `/usr/share/doc/northnarrow/`).
const RELEASE_ROOT_FILES: [&str; 3] = ["CHANGELOG.md", "NOTICES.md", "README-RELEASE.md"];
const GUIDES: &str = "docs/operator";
/// Scripts the release ships whose text an operator reads.
const SHIPPED_SCRIPTS: [&str; 2] = ["deploy/install.sh", "deploy/uninstall.sh"];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives one level below the repository root")
        .to_path_buf()
}

fn read(rel: &str) -> String {
    let path = repo_root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn exists(rel: &str) -> bool {
    repo_root().join(rel).is_file()
}

/// `docs/operator/*.md`, sorted.
fn guides() -> Vec<String> {
    let mut out: Vec<String> = fs::read_dir(repo_root().join(GUIDES))
        .expect("docs/operator")
        .map(|e| {
            e.expect("dir entry")
                .file_name()
                .into_string()
                .expect("utf-8 name")
        })
        .filter(|n| n.ends_with(".md"))
        .map(|n| format!("{GUIDES}/{n}"))
        .collect();
    out.sort();
    assert!(out.len() >= 5, "docs/operator has {} guides", out.len());
    out
}

/// The scripts and the guides: what the release ships for an operator to read.
fn shipped_texts() -> Vec<String> {
    let mut v: Vec<String> = SHIPPED_SCRIPTS.iter().map(|s| s.to_string()).collect();
    v.extend(guides());
    v
}

fn is_path_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '-')
}

fn is_url_char(c: char) -> bool {
    !c.is_whitespace() && !matches!(c, '<' | '>' | '(' | ')' | '"' | '\'' | '`' | '[' | ']')
}

/// One `….md` named in a text.
#[derive(Debug)]
struct Mention {
    line: usize,
    /// The path as written (`docs/operator/X.md`, `X.md`, `../y/Z.md`).
    path: String,
    /// The whole URL, when the path is the end of one.
    url: Option<String>,
    /// The rest of the line after `.md`.
    after: String,
}

/// Start of the run of characters before `end` that satisfy `pred`.
fn run_start(line: &str, end: usize, pred: fn(char) -> bool) -> usize {
    line[..end]
        .char_indices()
        .rev()
        .take_while(|(_, c)| pred(*c))
        .last()
        .map_or(end, |(k, _)| k)
}

fn mentions(text: &str) -> Vec<Mention> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let mut from = 0;
        while let Some(pos) = line[from..].find(".md") {
            let dot = from + pos;
            let end = dot + 3;
            from = end;
            if line[end..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                continue;
            }
            let start = run_start(line, dot, is_path_char);
            if start == dot {
                continue; // `*.md`, `.md` alone
            }
            let wstart = run_start(line, start, is_url_char);
            let word = &line[wstart..end];
            out.push(Mention {
                line: n + 1,
                path: line[start..end].to_string(),
                url: word.contains("://").then(|| word.to_string()),
                after: line[end..].to_string(),
            });
        }
    }
    out
}

/// `docs/operator/X.md` for a mention that names a guide, `None` otherwise.
fn guide_of(m: &Mention) -> Option<String> {
    if m.url.is_some() {
        return None;
    }
    let rel = if m.path.contains('/') {
        m.path.clone()
    } else {
        format!("{GUIDES}/{}", m.path)
    };
    (rel.starts_with(&format!("{GUIDES}/")) && exists(&rel)).then_some(rel)
}

/// Every problem with the documents `rel` names (DEP-018).
fn mention_problems(rel: &str, text: &str) -> Vec<String> {
    let mut bad = Vec::new();
    for m in mentions(text) {
        let at = format!(
            "{rel}:{}: `{}`",
            m.line,
            m.url.as_deref().unwrap_or(&m.path)
        );
        if let Some(url) = &m.url {
            if let Some(file) = url.strip_prefix(REPO_BLOB) {
                if !exists(file) {
                    bad.push(format!("{at}: no `{file}` in the repository"));
                }
            } else if url.contains(REPO) {
                bad.push(format!("{at}: name a repository file as {REPO_BLOB}<path>"));
            }
        } else if m.path.starts_with("docs/") {
            if !m.path.starts_with(&format!("{GUIDES}/")) {
                bad.push(format!(
                    "{at}: not shipped (the release has docs/operator/ only): point to a guide, or to {REPO_BLOB}{}",
                    m.path
                ));
            } else if !exists(&m.path) {
                bad.push(format!("{at}: no such guide"));
            }
        } else if m.path.contains('/') {
            bad.push(format!(
                "{at}: a path out of docs/operator — the release ships the guides alone; use a guide's name or a {REPO_BLOB} URL"
            ));
        } else if !RELEASE_ROOT_FILES.contains(&m.path.as_str())
            && !exists(&format!("{GUIDES}/{}", m.path))
        {
            bad.push(format!("{at}: neither a guide nor a file of the release"));
        }
    }
    bad
}

/// GitHub's anchor for a heading: lower case, spaces to `-`, punctuation
/// other than `-` and `_` dropped.
fn slug(heading: &str) -> String {
    heading
        .trim()
        .to_lowercase()
        .chars()
        .filter_map(|c| match c {
            ' ' => Some('-'),
            '-' | '_' => Some(c),
            c if c.is_alphanumeric() => Some(c),
            _ => None,
        })
        .collect()
}

/// The headings of a Markdown file, fenced code blocks skipped.
fn headings(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut fenced = false;
    for line in text.lines() {
        let t = line.trim_start();
        if t.starts_with("```") || t.starts_with("~~~") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            continue;
        }
        let hashes = t.chars().take_while(|&c| c == '#').count();
        if (1..=6).contains(&hashes) && t[hashes..].starts_with(' ') {
            out.push(t[hashes..].trim().to_string());
        }
    }
    out
}

/// The anchors GitHub gives the headings of a file (`-1`, `-2` for repeats).
fn anchors(text: &str) -> BTreeSet<String> {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut out = BTreeSet::new();
    for h in headings(text) {
        let base = slug(&h);
        let n = seen.entry(base.clone()).or_insert(0);
        out.insert(if *n == 0 {
            base.clone()
        } else {
            format!("{base}-{n}")
        });
        *n += 1;
    }
    out
}

/// `dir/target` with `.` and `..` resolved; `None` above the repository.
fn resolve(dir: &Path, target: &str) -> Option<String> {
    let mut parts: Vec<String> = Vec::new();
    for c in dir.join(target).components() {
        match c {
            Component::Normal(p) => parts.push(p.to_str()?.to_string()),
            Component::ParentDir => {
                parts.pop()?;
            }
            Component::CurDir => {}
            _ => return None,
        }
    }
    Some(parts.join("/"))
}

/// The targets of the Markdown links `[…](target)` of a line.
fn link_targets(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(pos) = line[from..].find("](") {
        let start = from + pos + 2;
        match line[start..].find(')') {
            Some(len) => {
                out.push(line[start..start + len].trim().to_string());
                from = start + len;
            }
            None => break,
        }
    }
    out
}

/// Links of `rel` that go into docs/operator resolve, anchor included;
/// from a guide, every relative link stays among the guides.
fn link_problems(rel: &str) -> Vec<String> {
    let text = read(rel);
    let dir = Path::new(rel).parent().unwrap_or(Path::new(""));
    let from_guide = rel.starts_with(&format!("{GUIDES}/"));
    let mut bad = Vec::new();
    let mut fenced = false;
    for (n, line) in text.lines().enumerate() {
        let t = line.trim_start();
        if t.starts_with("```") || t.starts_with("~~~") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            continue;
        }
        for target in link_targets(line) {
            if target.starts_with("http://")
                || target.starts_with("https://")
                || target.starts_with("mailto:")
            {
                continue;
            }
            let at = format!("{rel}:{}: link `{target}`", n + 1);
            let (path, anchor) = match target.split_once('#') {
                Some((p, a)) => (p, Some(a)),
                None => (target.as_str(), None),
            };
            let file = if path.is_empty() {
                Some(rel.to_string())
            } else {
                resolve(dir, path)
            };
            let Some(file) = file else {
                bad.push(format!("{at}: resolves above the repository"));
                continue;
            };
            let into_guides = file.starts_with(&format!("{GUIDES}/"));
            if from_guide && !into_guides {
                bad.push(format!(
                    "{at}: leaves docs/operator, which is all the release ships: link a guide or a {REPO_BLOB} URL"
                ));
                continue;
            }
            if !into_guides {
                continue;
            }
            if !exists(&file) {
                bad.push(format!("{at}: no `{file}`"));
                continue;
            }
            if let Some(anchor) = anchor {
                if !anchors(&read(&file)).contains(anchor) {
                    bad.push(format!(
                        "{at}: `{file}` has no heading with anchor `#{anchor}`"
                    ));
                }
            }
        }
    }
    bad
}

/// What a `§…` or `(section …)` after a guide's name asks of its headings.
fn section_ref(after: &str) -> Option<(String, Option<String>)> {
    let rest = after.trim_start_matches(&['`', ')'][..]);
    let rest = rest
        .strip_prefix(" §")
        .or_else(|| rest.strip_prefix(" (section "))
        .or_else(|| rest.strip_prefix(" section "))?;
    let num: String = rest
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let num = num.trim_end_matches('.').to_string();
    if num.is_empty() {
        return None;
    }
    let tail = &rest[rest
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(rest.len())..];
    let q = tail
        .strip_prefix(" Q")
        .map(|t| {
            t.chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
        })
        .filter(|d| !d.is_empty())
        .map(|d| format!("Q{d}"));
    Some((num, q))
}

/// The title quoted after a guide's name (`X.md`, "Title"), if any.
fn quoted_title(after: &str) -> Option<String> {
    let rest = after
        .trim_start_matches('`')
        .strip_prefix(',')?
        .trim_start();
    let rest = rest
        .strip_prefix("\\\"")
        .or_else(|| rest.strip_prefix('"'))?;
    let end = rest.find('"')?;
    Some(rest[..end].trim_end_matches('\\').to_string())
}

fn plain(s: &str) -> String {
    s.replace('`', "").to_lowercase()
}

/// Section references after a guide's name name a section it has.
fn section_problems(rel: &str, text: &str) -> Vec<String> {
    let mut bad = Vec::new();
    for m in mentions(text) {
        let Some(guide) = guide_of(&m) else { continue };
        let heads = headings(&read(&guide));
        let at = format!("{rel}:{}: `{}`", m.line, m.path);
        if let Some((num, q)) = section_ref(&m.after) {
            let found = heads.iter().any(|h| match &q {
                Some(q) => h.contains(&format!("§{num} {q}")),
                None => {
                    h.starts_with(&format!("{num} "))
                        || h.starts_with(&format!("{num}. "))
                        || h.contains(&format!("§{num}"))
                }
            });
            if !found {
                let q = q.map(|q| format!(" {q}")).unwrap_or_default();
                bad.push(format!("{at} §{num}{q}: no such section in {guide}"));
            }
        }
        if let Some(title) = quoted_title(&m.after) {
            if !heads.iter().any(|h| plain(h).contains(&plain(&title))) {
                bad.push(format!("{at} \"{title}\": no heading of {guide} says that"));
            }
        }
    }
    bad
}

#[test]
fn the_release_ships_the_operator_guides_and_no_other_document() {
    // The premise of the checks below, read from the packaging scripts.
    for script in [
        "deploy/release/mk-tarball.sh",
        "deploy/release/mk-packages.sh",
    ] {
        let text = read(script);
        assert!(
            text.contains("docs/operator/*.md"),
            "{script}: no longer copies docs/operator/*.md — revisit xtask/tests/operator_docs.rs"
        );
        for (n, line) in text.lines().enumerate() {
            let mut rest = line;
            while let Some(pos) = rest.find("docs/") {
                let tail = &rest[pos + 5..];
                assert!(
                    tail.starts_with("operator"),
                    "{script}:{}: ships or names another documentation directory ({line}) — revisit xtask/tests/operator_docs.rs",
                    n + 1
                );
                rest = tail;
            }
        }
    }
    let tarball = read("deploy/release/mk-tarball.sh");
    for f in RELEASE_ROOT_FILES {
        assert!(
            tarball.contains(f),
            "mk-tarball.sh: {f} is no longer at the root of the release"
        );
    }
}

#[test]
fn shipped_texts_name_only_shipped_documents_or_repository_urls() {
    let mut bad = Vec::new();
    for rel in shipped_texts() {
        bad.extend(mention_problems(&rel, &read(&rel)));
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn links_into_the_guides_resolve_with_their_anchors() {
    let mut bad = Vec::new();
    let mut files = guides();
    // Not shipped, but they send readers to the guides.
    files.extend(["README.md", "docs/TAPPA7_PREREQ.md"].map(String::from));
    for rel in files {
        bad.extend(link_problems(&rel));
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn section_references_after_a_guide_name_exist() {
    let mut bad = Vec::new();
    let mut files = shipped_texts();
    files.extend(
        [
            "README.md",
            "docs/TAPPA7_PREREQ.md",
            "docs/integration-test-runbook.md",
            "crates/nn-linux/src/host_hardening.rs",
        ]
        .map(String::from),
    );
    for rel in files {
        bad.extend(section_problems(&rel, &read(&rel)));
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// DEP-013: `lsm=` followed by a module name is a fixed list.
fn fixed_lsm_lists(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let mut rest = line;
        while let Some(pos) = rest.find("lsm=") {
            let tail = &rest[pos + 4..];
            if tail.starts_with(|c: char| c.is_ascii_lowercase()) {
                out.push(format!("{}: {}", n + 1, line.trim()));
            }
            rest = tail;
        }
    }
    out
}

#[test]
fn no_operator_facing_text_hands_out_a_fixed_lsm_list() {
    let mut files = shipped_texts();
    files.extend(
        [
            "README.md",
            "docs/TAPPA7_PREREQ.md",
            "docs/integration-test-runbook.md",
            "crates/nn-linux/src/host_hardening.rs",
        ]
        .map(String::from),
    );
    let mut bad = Vec::new();
    for rel in files {
        for hit in fixed_lsm_lists(&read(&rel)) {
            bad.push(format!("{rel}:{hit}"));
        }
    }
    assert!(
        bad.is_empty(),
        "a fixed `lsm=` list replaces the kernel's and can switch SELinux or AppArmor off; \
         point to docs/operator/KERNEL_COMPATIBILITY.md (\"Enabling the bpf LSM\") instead:\n{}",
        bad.join("\n")
    );
}

#[test]
fn the_bpf_lsm_procedure_extends_the_running_list_on_both_families() {
    let text = read("docs/operator/KERNEL_COMPATIBILITY.md");
    let start = text
        .find("## Enabling the `bpf` LSM")
        .expect("KERNEL_COMPATIBILITY.md: no \"Enabling the `bpf` LSM\" section");
    let end = text[start + 3..]
        .find("\n## ")
        .map_or(text.len(), |i| start + 3 + i);
    let section = &text[start..end];
    for needle in [
        "/proc/cmdline",              // an lsm= already there is the base
        "CONFIG_LSM",                 // otherwise the list lsm= replaces
        "/sys/kernel/security/lsm",   // what runs now, kept for the check
        "MISSING",                    // a running module left out stops it
        "update-grub",                // Debian / Ubuntu
        "grubby --update-kernel=ALL", // RHEL family
        "getenforce",                 // SELinux still enforcing
        "/sys/module/apparmor/parameters/enabled",
    ] {
        assert!(section.contains(needle), "the procedure lost `{needle}`");
    }
}

// The checker itself, on texts that must fail.

#[test]
fn the_checker_refuses_unshipped_documents_and_dead_links() {
    let bad = mention_problems(
        "deploy/install.sh",
        "echo \"see docs/TAPPA7_PREREQ.md and docs/operator/NOPE.md\"\n\
         echo \"https://github.com/northnarrow/northnarrow-new/blob/main/docs/design/NOPE.md\"\n\
         echo \"https://github.com/northnarrow/northnarrow-new/blob/v1/docs/PERFORMANCE.md\"\n\
         echo \"../audit/EXTERNAL_AUDIT_16f7563.md\"\n",
    );
    assert_eq!(bad.len(), 5, "{bad:#?}");
    let ok = mention_problems(
        "deploy/install.sh",
        "echo \"docs/operator/KERNEL_COMPATIBILITY.md CHANGELOG.md *.md\"\n\
         echo \"https://github.com/northnarrow/northnarrow-new/blob/main/docs/PERFORMANCE.md\"\n",
    );
    assert!(ok.is_empty(), "{ok:#?}");

    let secs = section_problems(
        "x",
        "docs/operator/COMBAT_RECOVERY.md §2 and INSTALL_UPGRADE_UNINSTALL.md §99,\n\
         docs/operator/TAPPA9_FIM_TRUST_MODEL.md §13 Q7 and §13 Q99 (no name)\n\
         `KERNEL_COMPATIBILITY.md`, \"Enabling the `bpf` LSM\" and\n\
         `KERNEL_COMPATIBILITY.md`, \"No such title\"\n",
    );
    assert_eq!(secs.len(), 2, "{secs:#?}");

    assert_eq!(
        fixed_lsm_lists("lsm=…,bpf `lsm=` lsm=$new\nlsm=lockdown,yama,bpf\n").len(),
        1
    );
    assert_eq!(
        slug("3.8 No new entries in the agent's directories (external audit EBPF-015)"),
        "38-no-new-entries-in-the-agents-directories-external-audit-ebpf-015"
    );
    assert_eq!(
        slug("Enabling the `bpf` LSM (kernel command line)"),
        "enabling-the-bpf-lsm-kernel-command-line"
    );
}
