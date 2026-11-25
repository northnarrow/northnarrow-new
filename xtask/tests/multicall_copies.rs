//! Lot 344: no copy of a coreutils program is run under another name — by
//! a lab script or by a test.
//!
//! On Ubuntu 26.04 (a lab guest, and the hosted CI runners' release) the
//! coreutils are uutils' one multicall binary, which picks its utility from
//! the name it is run by: a copy of `sleep` named `nn-corpus-control` or
//! `mal` printed "coreutils: unknown program …" and exited 1 at once. The
//! dev corpus's control (a program from /tmp: recorded for the lab user,
//! killed for www-data) proved nothing there, and
//! `combat::actuator::tests::neutralize_quarantines_the_offenders_binary`
//! failed on the runners whenever NEUTRALIZE read its child after that exit
//! (NO_BINARY, #549's CI twice). A copy keeps the utility's name in a
//! directory of its own, or is a copy of the shell looping on `sleep 1`.
//! Offline: committed files only.
//!
//! Lot 1.7a (stage S1, item F12): the Rust half reads the sources as Rust
//! (`support::ast`). The lexical one looked for `copy("` on one line, and
//! the re-check of #554 passed it with rustfmt's form (the source on the
//! next line) and a source held in a variable. A copy is now any call of
//! `copy` (`fs::copy`, `io::copy` of a `File::open`) whose source can be a
//! coreutils program — a literal, a `const`, a variable, a parameter, an
//! array's item, in parentheses —, a link (`hard_link`, `symlink`) of the
//! program itself, a `write` of what a `read` of it gave, and a `cp`,
//! `install` or `ln` a `Command` runs; its destination's name is what the
//! expression can hold (`join`, `format!`, a variable). The shell half
//! joins a line continued with `\` to the next before it reads it. The
//! lexical reader (kept in [`lexical`] only to show it) missed each
//! spelling planted below.

mod support;

use std::fs;
use std::path::{Path, PathBuf};

use support::ast::{self, Corpus};
use support::repo_root;

/// Lot 344: every shell script under `dir`, sorted.
fn sh_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries {
        let p = e.unwrap().path();
        if p.is_dir() {
            sh_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "sh") {
            out.push(p);
        }
    }
    out.sort();
}

/// Lot 344: the coreutils a lab script copies to run under another name.
const MULTICALL_UTILS: &[&str] = &[
    "sleep", "true", "false", "id", "ls", "cat", "env", "head", "tail", "yes", "echo", "touch",
    "dd", "cp", "mv", "rm", "ln", "mkdir", "date", "printf", "stat", "tee", "timeout",
];

/// Lot 344: the copies made before the ratchet, on scripts that do not run
/// on Ubuntu 26.04's lab round or keep a name the test reads — each a
/// residual of its own, never a pattern to follow (a new one fails).
const KNOWN_RENAMED_COPIES: &[&str] = &[
    // the review of #554 (F4): by `cat`, seen since — each copy is the
    // program with random bytes appended (a new file id), run for its exec
    "deploy/lab/execq/execq-check.sh: /usr/bin/true \"$1\"",
    "deploy/lab/execq/execq-check.sh: /usr/bin/true \"$S\"",
    "deploy/lab/execq/execq-check.sh: /usr/bin/true \"$B\"",
    "deploy/lab/execq/execq-check.sh: /usr/bin/true \"$f\"",
    "deploy/lab/heartbeat/watch-lab.sh: /bin/sleep /tmp/nn-hb-kill",
    "deploy/lab/release/release-check.sh: /bin/true /tmp/nn-release-probe",
    "deploy/lab/bus/responses.sh: /bin/sleep \"$STAGE/nn-exp13r-crash\"",
    "deploy/lab/bus/responses.sh: /bin/sleep \"$STAGE/nn-exp13r-hang\"",
    "deploy/lab/bus/responses.sh: /bin/sleep \"$STAGE/nn-exp13r-k$i\"",
    "deploy/lab/pkgmgr/mk-probe-rpm.sh: /bin/true %{buildroot}/usr/lib/nn-pkgprobe/nn-pkgprobe-suid",
    "deploy/lab/pkgmgr/mk-probe-deb.sh: /bin/true \"$root/usr/lib/nn-pkgprobe/nn-pkgprobe-suid\"",
    "deploy/lab/exec-sensor/exec-sensor-check.sh: /bin/sleep \"$X\"",
    "deploy/lab/export/export-guest.sh: /bin/true /tmp/nn-export-lab-x",
    "deploy/lab/execq/execq-check.sh: /usr/bin/ls \"$U\"",
    "deploy/lab/adversarial/anti-tamper.sh: /bin/true \"$TMPD/nn-sat\"",
];

/// `line` with each lookup of a coreutils program by name
/// (`$(command -v sleep)`, `$(which sleep)`, in backquotes too) written as
/// its path (the review of #554, F4).
fn resolved_lookups(line: &str) -> String {
    let mut out = line.to_string();
    for u in MULTICALL_UTILS {
        for form in [
            format!("$(command -v {u})"),
            format!("$(which {u})"),
            format!("`command -v {u}`"),
            format!("`which {u}`"),
        ] {
            out = out.replace(&form, &format!("/usr/bin/{u}"));
        }
    }
    out
}

/// `(source, destination)` of each `cp`/`install`/`ln` (the review of
/// #554, F4: and `cat … >`) of a coreutils program on `line` whose
/// destination does not keep the program's name.
fn renamed_util_copies(line: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let line = resolved_lookups(line);
    let words: Vec<&str> = line
        .split(|c: char| c.is_whitespace() || c == ';' || c == '(' || c == ')' || c == '\'')
        .filter(|w| !w.is_empty())
        .collect();
    for (i, w) in words.iter().enumerate() {
        if *w == "cat" {
            // `cat /bin/sleep > dst`, `cat /bin/sleep >dst`
            let src = words[i + 1..].iter().find(|a| !a.starts_with('-'));
            let to = words[i + 1..].iter().position(|a| a.starts_with('>'));
            let dst = to.and_then(|j| match words[i + 1 + j].trim_start_matches('>') {
                "" => words.get(i + 2 + j).copied(),
                d => Some(d),
            });
            if let (Some(src), Some(dst)) = (src, dst) {
                if let Some(found_one) = renamed(src, dst) {
                    found.push(found_one);
                }
            }
            continue;
        }
        if *w != "cp" && *w != "install" && *w != "ln" {
            continue;
        }
        // the first non-option word is the source, the next the destination
        let mut rest = words[i + 1..].iter().filter(|a| !a.starts_with('-'));
        // `install -m 755`: the mode's value is not an operand
        let (Some(src), Some(dst)) = (rest.next(), rest.next()) else {
            continue;
        };
        let (src, dst) = if src.chars().all(|c| c.is_ascii_digit()) {
            match (Some(dst), rest.next()) {
                (Some(s), Some(d)) => (s, d),
                _ => continue,
            }
        } else {
            (src, dst)
        };
        if let Some(found_one) = renamed(src, dst) {
            found.push(found_one);
        }
    }
    found
}

/// Lot 1.7a: a script's lines, each one continued with `\\` joined to the
/// next (`cp \\` / `  /bin/sleep /tmp/mal` is one command).
fn joined_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for line in text.lines() {
        match line.strip_suffix('\\') {
            Some(head) if !line.trim_start().starts_with('#') => {
                cur.push_str(head);
                cur.push(' ');
            }
            _ => {
                cur.push_str(line);
                out.push(std::mem::take(&mut cur));
            }
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// `(src, dst)` when `src` is a coreutils program and `dst` does not keep
/// its name.
fn renamed(src: &str, dst: &str) -> Option<(String, String)> {
    let path = src.trim_matches('"');
    let util = path
        .strip_prefix("/usr/bin/")
        .or_else(|| path.strip_prefix("/bin/"))?;
    if !MULTICALL_UTILS.contains(&util) {
        return None;
    }
    let leaf = dst.trim_matches('"').rsplit('/').next().unwrap_or("");
    (leaf != util).then(|| (src.to_string(), dst.to_string()))
}

/// Lot 344 (named, item 8): on Ubuntu 26.04 the coreutils are uutils' one
/// multicall binary, which picks its utility from the name it is run by — a
/// copy of `sleep` named `/tmp/nn-corpus-control` printed "unknown program"
/// and exited 1, so the corpus's control (a program from /tmp: recorded for
/// the lab user, killed for www-data) proved nothing there. No lab script
/// runs a copy of a coreutils program under another name (a shell copy
/// looping on `sleep 1`, or a copy that keeps the name in a directory of its
/// own); the copies made before the ratchet are listed, each a residual.
#[test]
fn no_lab_script_runs_a_coreutils_copy_under_another_name() {
    assert_eq!(
        renamed_util_copies("install -m 755 /bin/sleep /tmp/nn-corpus-control"),
        vec![("/bin/sleep".into(), "/tmp/nn-corpus-control".into())]
    );
    assert!(renamed_util_copies("install -m 755 /bin/sh /tmp/nn-corpus-control").is_empty());
    assert!(renamed_util_copies("cp /usr/bin/true \"$APPD/AppRun/true\"").is_empty());
    // the review of #554 (F4): a link, a lookup by name, a `cat`
    for (line, src, dst) in [
        ("ln -sf /bin/sleep /tmp/nn-x", "/bin/sleep", "/tmp/nn-x"),
        (
            "ln /usr/bin/sleep \"$D/mal\"",
            "/usr/bin/sleep",
            "\"$D/mal\"",
        ),
        (
            "cp \"$(command -v sleep)\" /tmp/mal",
            "\"/usr/bin/sleep\"",
            "/tmp/mal",
        ),
        (
            "install -m 755 `which sleep` /tmp/mal",
            "/usr/bin/sleep",
            "/tmp/mal",
        ),
        (
            "cat /bin/sleep > /tmp/mal; chmod +x /tmp/mal",
            "/bin/sleep",
            "/tmp/mal",
        ),
        ("cat /bin/sleep >/tmp/mal", "/bin/sleep", "/tmp/mal"),
    ] {
        assert_eq!(
            renamed_util_copies(line),
            vec![(src.to_string(), dst.to_string())],
            "{line}"
        );
    }
    for line in [
        "ln -s /bin/sleep \"$D/sleep\"",
        "cat /etc/hostname > /tmp/x",
        "cp \"$(command -v sh)\" /tmp/mal",
    ] {
        assert!(renamed_util_copies(line).is_empty(), "{line}");
    }
    let mut files = Vec::new();
    sh_files(&repo_root().join("deploy/lab"), &mut files);
    assert!(files.len() > 20, "{} lab scripts", files.len());
    let mut new = Vec::new();
    let mut seen_known = std::collections::BTreeSet::new();
    for f in &files {
        let rel = f
            .strip_prefix(repo_root())
            .unwrap()
            .to_string_lossy()
            .into_owned();
        for line in joined_lines(&fs::read_to_string(f).unwrap()) {
            if line.trim_start().starts_with('#') {
                continue;
            }
            for (src, dst) in renamed_util_copies(&line) {
                let entry = format!("{rel}: {src} {dst}");
                if KNOWN_RENAMED_COPIES.contains(&entry.as_str()) {
                    seen_known.insert(entry);
                } else {
                    new.push(entry);
                }
            }
        }
    }
    assert!(
        new.is_empty(),
        "a coreutils program copied under another name (uutils' multicall binary on Ubuntu \
         26.04 runs no utility of that name: rc 1) — copy the shell and loop, or keep the \
         name: {new:#?}"
    );
    // the list shrinks with the sites it names
    let stale: Vec<_> = KNOWN_RENAMED_COPIES
        .iter()
        .filter(|k| !seen_known.contains(**k))
        .collect();
    assert!(
        stale.is_empty(),
        "listed copies no longer there: {stale:#?}"
    );
}

/// The util a path names (`/bin/sleep`, `/usr/bin/sleep`), if a coreutils
/// one.
fn util_of(path: &str) -> Option<&'static str> {
    let p = path.trim_matches('"');
    let u = p
        .strip_prefix("/usr/bin/")
        .or_else(|| p.strip_prefix("/bin/"))?;
    MULTICALL_UTILS.iter().copied().find(|x| *x == u)
}

/// The leaf of a path value (`{?}/mal/` is `mal`), `?` when unknown.
fn leaf(v: &str) -> String {
    let t = v.trim_matches('"').trim_end_matches('/');
    let l = t.rsplit('/').next().unwrap_or(t);
    if l.is_empty() || l.contains(ast::UNKNOWN) {
        "?".to_string()
    } else {
        l.to_string()
    }
}

/// `e` under a `File::open(p)`, `File::create(p)`, `&mut`, `?`, an
/// `unwrap`/`expect`: the path it names.
fn path_expr(e: &syn::Expr) -> &syn::Expr {
    let mut e = ast::peel(e);
    loop {
        match e {
            syn::Expr::MethodCall(m)
                if [
                    "unwrap",
                    "expect",
                    "as_path",
                    "clone",
                    "as_ref",
                    "to_path_buf",
                ]
                .contains(&m.method.to_string().as_str()) =>
            {
                e = ast::peel(&m.receiver)
            }
            syn::Expr::Call(c)
                if c.args.len() == 1
                    && matches!(ast::peel(&c.func), syn::Expr::Path(p)
                        if ["open", "create"].contains(&ast::last(&p.path).as_str())) =>
            {
                e = ast::peel(&c.args[0])
            }
            _ => return e,
        }
    }
}

/// A local variable a path expression is (`&mal`, `mal.as_path()`).
fn var_of(e: &syn::Expr) -> Option<String> {
    match path_expr(e) {
        syn::Expr::Path(p) if p.path.segments.len() == 1 => Some(ast::last(&p.path)),
        _ => None,
    }
}

/// The coreutils programs `e` can name.
fn utils_in(
    c: &Corpus<'_>,
    rel: &str,
    e: &syn::Expr,
    scope: Option<ast::FnId>,
) -> Vec<&'static str> {
    let mut u: Vec<&str> = c
        .values(rel, path_expr(e), scope)
        .iter()
        .filter_map(|v| util_of(v))
        .collect();
    u.sort();
    u.dedup();
    u
}

/// The leaves a destination can have (`?` when none is known).
fn leaves(c: &Corpus<'_>, rel: &str, e: &syn::Expr, scope: Option<ast::FnId>) -> Vec<String> {
    let v = c.values(rel, path_expr(e), scope);
    if v.is_empty() {
        return vec!["?".to_string()];
    }
    let mut l: Vec<String> = v.iter().map(|x| leaf(x)).collect();
    l.sort();
    l.dedup();
    l
}

/// Whether `e` holds what a read of a coreutils program gave (`fs::read(
/// "/bin/sleep")`, or a variable bound to it): the program.
fn read_of_util(
    c: &Corpus<'_>,
    rel: &str,
    e: &syn::Expr,
    scope: Option<ast::FnId>,
    depth: u8,
) -> Option<&'static str> {
    if depth > 4 {
        return None;
    }
    match path_expr(e) {
        syn::Expr::Call(call)
            if matches!(ast::peel(&call.func), syn::Expr::Path(p) if ast::last(&p.path) == "read")
                && call.args.len() == 1 =>
        {
            utils_in(c, rel, &call.args[0], scope).first().copied()
        }
        syn::Expr::Path(p) if p.path.segments.len() == 1 => c
            .bound(rel, scope, &ast::last(&p.path))
            .iter()
            .find_map(|b| read_of_util(c, rel, b.expr, b.scope, depth + 1)),
        _ => None,
    }
}

/// `(line, utility, destination leaf)` of each copy of a coreutils program
/// in `rel` (see the module's doc) whose destination does not keep the
/// utility's name — or that cannot be read here (`?`) —, and of each link
/// or rename (`hard_link`, `symlink`, `rename`) of a copy that kept it, in
/// the same function, to another name. A copy renamed into place by the
/// utility's name is none.
fn renamed_copies(c: &Corpus<'_>, rel: &str) -> Vec<(usize, &'static str, String, String)> {
    let ix = &c.files[rel];
    let mut found = Vec::new();
    let moves = |scope: Option<ast::FnId>, var: &str| -> Vec<(usize, Vec<String>)> {
        ix.calls
            .iter()
            .filter(|m| {
                m.scope == scope
                    && ["hard_link", "symlink", "rename", "symlink_file"].contains(&m.name.as_str())
                    && m.args.len() == 2
                    && var_of(m.args[0]).as_deref() == Some(var)
            })
            .map(|m| (m.line, leaves(c, rel, m.args[1], m.scope)))
            .collect()
    };
    for call in &ix.calls {
        let name = call.name.as_str();
        let (utils, dst): (Vec<&str>, Option<&syn::Expr>) = match name {
            "copy" if call.args.len() == 2 => (
                utils_in(c, rel, call.args[0], call.scope),
                Some(call.args[1]),
            ),
            "hard_link" | "symlink" | "symlink_file" if call.args.len() == 2 => (
                utils_in(c, rel, call.args[0], call.scope),
                Some(call.args[1]),
            ),
            "write" if call.args.len() == 2 && call.receiver.is_none() => (
                read_of_util(c, rel, call.args[1], call.scope, 0)
                    .into_iter()
                    .collect(),
                Some(call.args[0]),
            ),
            "new"
                if call
                    .path
                    .as_ref()
                    .is_some_and(|p| ast::path_ends(p, &["Command", "new"])) =>
            {
                // `Command::new("cp").args([src, dst])`: the operands in order
                let prog = c.values(rel, call.args[0], call.scope);
                if !prog
                    .iter()
                    .any(|p| ["cp", "install", "ln"].contains(&leaf(p).as_str()))
                {
                    continue;
                }
                let (_, chain, _) = ast::spine(call.expr, &call.anc);
                let mut ops: Vec<&syn::Expr> = Vec::new();
                for m in chain {
                    match m.method.to_string().as_str() {
                        "arg" => ops.extend(m.args.iter()),
                        "args" => match ast::peel(&m.args[0]) {
                            syn::Expr::Array(a) => ops.extend(a.elems.iter()),
                            other => ops.push(other),
                        },
                        _ => {}
                    }
                }
                let vals: Vec<String> = ops
                    .iter()
                    .map(|o| {
                        c.values(rel, o, call.scope)
                            .into_iter()
                            .next()
                            .unwrap_or_default()
                    })
                    .filter(|v| !v.starts_with('-'))
                    .collect();
                let vals: Vec<String> = match vals.first() {
                    Some(v) if v.chars().all(|ch| ch.is_ascii_digit()) => vals[1..].to_vec(),
                    _ => vals,
                };
                if let (Some(src), Some(dst)) = (vals.first(), vals.get(1)) {
                    if let Some(u) = util_of(src) {
                        let l = leaf(dst);
                        if l != u {
                            found.push((call.line, "copy", u.to_string(), l));
                        }
                    }
                }
                continue;
            }
            _ => continue,
        };
        let Some(dst) = dst else { continue };
        let kind = if name == "copy" || name == "write" {
            "copy"
        } else {
            "link"
        };
        for util in utils {
            let ls = leaves(c, rel, dst, call.scope);
            let renamed: Vec<&String> = ls.iter().filter(|l| *l != util).collect();
            let var = var_of(dst);
            let mv = var
                .as_deref()
                .map(|v| moves(call.scope, v))
                .unwrap_or_default();
            if let Some(l) = renamed.first() {
                // a copy renamed into place, by the utility's name, before it runs
                if !(name == "copy" && mv.iter().any(|(_, to)| to.iter().all(|t| t == util))) {
                    found.push((call.line, kind, util.to_string(), (*l).clone()));
                }
                continue;
            }
            // the copy keeps the name: a link or rename of it to another
            for (m, to) in mv {
                if let Some(t) = to.iter().find(|t| *t != util) {
                    found.push((m, "copy", util.to_string(), t.clone()));
                }
            }
        }
    }
    found.sort();
    found.dedup();
    found
}

/// `code` (a function's body) in a file of its own, parsed and indexed:
/// [`renamed_copies`] of it, its lines kept.
fn renamed_in(code: &str) -> Vec<(usize, String, String)> {
    let text = format!("fn f() {{ {code}\n}}\n");
    let parsed = ast::parse("fixture.rs", &text);
    let c = Corpus::new([("fixture.rs", text.as_str(), &parsed)]);
    renamed_copies(&c, "fixture.rs")
        .into_iter()
        .map(|(l, _, u, n)| (l, u, n))
        .collect()
}

/// Copies run under another name on purpose: only their exec is read (an
/// exec record, a barrier), never what the program does or how it exits.
const EXEC_ONLY_COPIES: &[&str] = &[
    "agent/tests/common/mod.rs: a copy of true named nn_barrier",
    "agent/tests/detection_rules_at_scale_privileged_e2e.rs: a copy of true named nnchain_quiet",
];

/// Lot 1.7a: the system's programs linked by a test's fixture under the
/// name of a `/proc/<pid>/exe` link (a fake procfs the code under test
/// reads the link of, never runs), or as a fixture root's module tool the
/// code under test only judges — the AST reader sees them (a direct link,
/// the program passed to a helper), the lexical one did not. Listed one by
/// one: a new link of a program to another name fails.
const LINK_FIXTURES: &[&str] = &[
    "crates/nn-core/src/posture/lineage.rs: a link of sleep named exe",
    "crates/nn-linux/src/sensors/exec_facts.rs: a link of env named exe",
    "crates/nn-linux/src/sensors/kmod_exec.rs: a link of env named exe",
    "crates/nn-linux/src/sensors/kmod_exec.rs: a link of sleep named exe",
    "crates/nn-linux/src/sensors/kmod_exec.rs: a link of true named exe",
    "crates/nn-linux/src/sensors/kmod_exec.rs: a link of true named ?",
    "crates/nn-linux/src/sensors/ring_drops.rs: a link of cat named exe",
];

/// Lot 344 (named, item 9: #549's CI failure, its root cause): no test runs
/// a copy of a coreutils program under another name — on the hosted
/// runners' uutils the child printed "unknown program" and exited at once.
#[test]
fn no_test_runs_a_coreutils_copy_under_another_name() {
    let probe = "        let mal = tmp.path().join(\"mal\");\n        std::fs::copy(\"/bin/sleep\", &mal).unwrap();\n        let c = std::process::Command::new(&mal).arg(\"60\").spawn();\n";
    assert_eq!(
        renamed_in(probe),
        vec![(2, "sleep".to_string(), "mal".to_string())]
    );
    let kept = "        let mal = tmp.path().join(\"mal\").join(\"sleep\");\n        std::fs::copy(\"/bin/sleep\", &mal).unwrap();\n        let c = std::process::Command::new(&mal).arg(\"60\").spawn();\n";
    assert!(renamed_in(kept).is_empty());
    // the review of #554 (F4): however the copy is then run, or made
    for (code, leaf) in [
        // run through another expression of the path
        (
            "let mal = tmp.path().join(\"mal\");\nstd::fs::copy(\"/bin/sleep\", &mal).unwrap();\nCommand::new(mal.as_path()).spawn();",
            "mal",
        ),
        (
            "let mal = tmp.path().join(\"mal\");\nfs::copy(\"/bin/sleep\", &*mal).unwrap();\nCommand::new(&*mal).spawn();",
            "mal",
        ),
        (
            "let mal: PathBuf = PathBuf::from(\"/tmp/x/mal\");\nfs::copy(\"/bin/sleep\", mal.clone()).unwrap();",
            "mal",
        ),
        // the destination inline
        (
            "fs::copy(\"/usr/bin/sleep\", dir.path().join(\"mal\")).unwrap();",
            "mal",
        ),
        // a path built where this test cannot read it
        ("fs::copy(\"/bin/sleep\", &helper_path()).unwrap();", "?"),
        // a copy that keeps the name, linked or renamed to another
        (
            "let s = d.join(\"sleep\");\nfs::copy(\"/bin/sleep\", &s).unwrap();\nstd::fs::hard_link(&s, d.join(\"mal\")).unwrap();",
            "mal",
        ),
        (
            "let s = d.join(\"sleep\");\nfs::copy(\"/bin/sleep\", &s).unwrap();\nlet m = d.join(\"mal\");\nstd::os::unix::fs::symlink(s.as_path(), &m).unwrap();",
            "mal",
        ),
        (
            "let s = d.join(\"sleep\");\nfs::copy(\"/bin/sleep\", &s).unwrap();\nfs::rename(&s, d.join(\"x\").join(\"evil\")).unwrap();",
            "evil",
        ),
    ] {
        let got = renamed_in(code);
        assert_eq!(got.len(), 1, "{code}: {got:?}");
        assert_eq!(got[0].2, leaf, "{code}");
    }
    // a link that keeps the name, of another file, a copy renamed into
    // place by the utility's name, or a copy of the shell
    for code in [
        "let sleep = tmp.path().join(\"sleep\");\nlet up = tmp.path().join(\"sleep.new\");\nfs::copy(\"/bin/sleep\", &up).unwrap();\nfs::rename(&up, &sleep).unwrap();",
        "let s = d.join(\"sleep\");\nfs::copy(\"/bin/sleep\", &s).unwrap();\nstd::fs::hard_link(&s, e.join(\"sleep\")).unwrap();",
        "let s = d.join(\"sleep\");\nfs::copy(\"/bin/sleep\", &s).unwrap();\nstd::fs::hard_link(&sleeper, d.join(\"mal\")).unwrap();",
        "fs::copy(\"/bin/sh\", dir.join(\"mal\")).unwrap();",
    ] {
        assert!(renamed_in(code).is_empty(), "{code}");
    }
    let mut sources = std::collections::BTreeMap::new();
    for top in ["agent", "crates", "watchdog", "cli", "scan", "xtask/src"] {
        sources.extend(ast::tree_sources(&repo_root(), top));
    }
    assert!(sources.len() > 100, "{} sources", sources.len());
    let parsed = ast::parse_all(&sources, false);
    let c = Corpus::of(&sources, &parsed);
    let mut bad = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for rel in sources.keys() {
        for (n, kind, util, leaf) in renamed_copies(&c, rel) {
            let entry = format!("{rel}: a {kind} of {util} named {leaf}");
            if EXEC_ONLY_COPIES.contains(&entry.as_str()) || LINK_FIXTURES.contains(&entry.as_str())
            {
                seen.insert(entry);
            } else {
                bad.push(format!("{entry} (line {n})"));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "a coreutils program run under another name exits at once on uutils (Ubuntu 26.04, \
         the hosted runners) — keep the name in a directory of its own: {bad:#?}"
    );
    // lot 1.7a: the lists shrink with the sites they name
    let stale: Vec<_> = EXEC_ONLY_COPIES
        .iter()
        .chain(LINK_FIXTURES)
        .filter(|k| !seen.contains(**k))
        .collect();
    assert!(stale.is_empty(), "listed sites no longer there: {stale:#?}");
}

/// Lot 1.7a: the spellings that passed the lexical reader — the re-check
/// of #554's two (rustfmt's form, a source held in a variable) and their
/// kin: the source in parentheses, in a `const`, an array's item, a
/// parameter; `io::copy` of a `File::open`; the program linked under
/// another name; a `write` of a `read` of it; `cp` run by a `Command`.
/// Each is also planted in a copy of a product test (`agent/tests/common/
/// mod.rs`, which holds an exec-only copy) and caught there.
#[test]
fn the_lexical_bypasses_are_caught() {
    let cases = [
        // the re-check of #554 (tmp/rev554-multicall-recheck)
        "std::fs::copy(\n    \"/usr/bin/sleep\",\n    tmp.path().join(\"a-renamed-copy-of-the-sleep-binary\"),\n)\n.expect(\"copy sleep\");",
        "let src = \"/bin/sleep\";\nstd::fs::copy(src, tmp.path().join(\"mal\")).unwrap();",
        // and their kin
        "std::fs::copy((\"/bin/sleep\"), tmp.path().join(\"mal\")).unwrap();",
        "for u in [\"/bin/sh\", \"/bin/sleep\"] { std::fs::copy(u, d.join(\"mal\")).unwrap(); }",
        "std::io::copy(&mut std::fs::File::open(\"/bin/sleep\").unwrap(), &mut std::fs::File::create(d.join(\"mal\")).unwrap()).unwrap();",
        "std::os::unix::fs::symlink(\"/bin/sleep\", d.join(\"mal\")).unwrap();",
        "std::fs::hard_link(\"/usr/bin/true\", d.join(\"mal\")).unwrap();",
        "let bytes = std::fs::read(\"/bin/sleep\").unwrap();\nstd::fs::write(d.join(\"mal\"), &bytes).unwrap();",
        "std::process::Command::new(\"cp\").args([\"/bin/sleep\", \"/tmp/mal\"]).status().unwrap();",
        "std::process::Command::new(\"install\").arg(\"-m\").arg(\"755\").arg(\"/bin/sleep\").arg(d.join(\"mal\")).status().unwrap();",
    ];
    for code in cases {
        assert!(
            lexical::renamed_spawned_copies(code).is_empty(),
            "the lexical reader saw it: {code}"
        );
        let got = renamed_in(code);
        assert_eq!(got.len(), 1, "{code}: {got:?}");
        assert_ne!(got[0].2, got[0].1, "{code}: {got:?}");
    }
    // the source in a `const`, or a helper's parameter: the file's items
    for text in [
        "const SLEEP: &str = \"/bin/sleep\";\nfn f(d: &std::path::Path) { std::fs::copy(SLEEP, d.join(\"mal\")).unwrap(); }\n",
        "fn put(src: &str, d: &std::path::Path) { std::fs::copy(src, d.join(\"mal\")).unwrap(); }\nfn f(d: &std::path::Path) { put(\"/bin/sleep\", d); }\n",
    ] {
        assert!(lexical::renamed_spawned_copies(text).is_empty(), "{text}");
        let parsed = ast::parse("fixture.rs", text);
        let c = Corpus::new([("fixture.rs", text, &parsed)]);
        let got = renamed_copies(&c, "fixture.rs");
        assert_eq!(got.len(), 1, "{text}: {got:?}");
    }
    // each planted in a copy of a product test file
    let host = "agent/tests/common/mod.rs";
    let text = fs::read_to_string(repo_root().join(host)).unwrap();
    let count = |t: &str| {
        let parsed = ast::parse(host, t);
        let c = Corpus::new([(host, t, &parsed)]);
        renamed_copies(&c, host).len()
    };
    let base = count(&text);
    let base_lex = lexical::renamed_spawned_copies(&text).len();
    for code in cases {
        let copy = format!(
            "{text}\nfn planted(tmp: &tempfile::TempDir, d: &std::path::Path) {{\n{code}\n}}\n"
        );
        assert_eq!(
            lexical::renamed_spawned_copies(&copy).len(),
            base_lex,
            "{code}"
        );
        assert_eq!(count(&copy), base + 1, "{code}");
    }
    // the shell's line continued with `\`
    let script = "cp \\\n  /bin/sleep \\\n  /tmp/mal\n";
    assert!(script.lines().all(|l| renamed_util_copies(l).is_empty()));
    let joined = joined_lines(script);
    assert_eq!(
        renamed_util_copies(&joined[0]),
        vec![("/bin/sleep".into(), "/tmp/mal".into())]
    );
}

/// The lexical reader of the Rust sources before lot 1.7a, kept only to
/// show the spellings it missed.
mod lexical {
    use super::MULTICALL_UTILS;

    /// The last component of the last string literal in `text`, `None`
    /// without one.
    fn last_literal_leaf(text: &str) -> Option<String> {
        let mut quotes = text.match_indices('"').map(|(i, _)| i);
        let mut last = None;
        while let (Some(a), Some(b)) = (quotes.next(), quotes.next()) {
            last = Some(&text[a + 1..b]);
        }
        let lit = last?.trim_end_matches('/');
        Some(lit.rsplit('/').next().unwrap_or(lit).to_string())
    }

    /// The first identifier in `expr` past `&`, `*` and spaces (`&mal`,
    /// `&*mal`, `mal.as_path()`, `mal.clone()`).
    fn first_ident(expr: &str) -> String {
        expr.trim_start_matches([',', ' ', '&', '*', '('])
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect()
    }

    /// Is `word` a whole identifier in `text`?
    fn has_ident(text: &str, word: &str) -> bool {
        !word.is_empty()
            && text.match_indices(word).any(|(i, _)| {
                let before = text[..i].chars().next_back();
                let after = text[i + word.len()..].chars().next();
                let id = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
                !id(before) && !id(after)
            })
    }

    /// The arguments of a call whose text after `(` is `text`, split at its
    /// own commas, up to its closing parenthesis.
    fn call_args(text: &str) -> Vec<&str> {
        let (mut depth, mut from, mut args) = (0i32, 0, Vec::new());
        let mut quoted = false;
        for (i, c) in text.char_indices() {
            match c {
                '"' => quoted = !quoted,
                _ if quoted => {}
                '(' | '[' => depth += 1,
                ')' | ']' if depth == 0 => {
                    args.push(&text[from..i]);
                    return args;
                }
                ')' | ']' => depth -= 1,
                ',' if depth == 0 => {
                    args.push(&text[from..i]);
                    from = i + 1;
                }
                _ => {}
            }
        }
        args.push(&text[from..]);
        args
    }

    /// The leaf the path expression `expr` (one argument, on `lines[n]`)
    /// names: a literal in the expression itself (`dir.join("mal")`,
    /// `"/tmp/mal"`), else the last literal of `let var = …` (`var` its first
    /// identifier) up to 40 lines above; `"?"` when neither says (a path built
    /// elsewhere). With `var`.
    fn leaf_of(lines: &[&str], n: usize, expr: &str) -> (String, String) {
        let var = first_ident(expr);
        if expr.contains('"') {
            return (var, last_literal_leaf(expr).unwrap_or_else(|| "?".into()));
        }
        let built = lines[n.saturating_sub(40)..n]
            .iter()
            .rev()
            .find(|l| l.contains(&format!("let {var} = ")) || l.contains(&format!("let {var}: ")))
            .and_then(|l| last_literal_leaf(l));
        (var, built.unwrap_or_else(|| "?".into()))
    }

    /// `(line number, utility, destination leaf)` of each copy in `code` of a
    /// coreutils program (`fs::copy("/bin/sleep", …)`) whose destination does
    /// not keep the utility's name — or that cannot be read here (`"?"`) —
    /// and of each link or rename (`hard_link`, `symlink`, `rename`) of such a
    /// copy to another name within 30 lines. The review of #554 (F4): whether
    /// it is then run, and how (`Command::new(mal.as_path())`, `&*mal`,
    /// `.clone()`, `PathBuf::from`), is no longer asked: a copy of a uutils
    /// program under another name is run by that name or not made.
    pub fn renamed_spawned_copies(code: &str) -> Vec<(usize, String, String)> {
        let lines: Vec<&str> = code.lines().collect();
        let mut found = Vec::new();
        for (n, line) in lines.iter().enumerate() {
            let Some(at) = line.find("copy(\"") else {
                continue;
            };
            let rest = &line[at + "copy(\"".len()..];
            let Some(end) = rest.find('"') else {
                continue;
            };
            let src = &rest[..end];
            let Some(util) = src
                .strip_prefix("/usr/bin/")
                .or_else(|| src.strip_prefix("/bin/"))
            else {
                continue;
            };
            if !MULTICALL_UTILS.contains(&util) {
                continue;
            }
            let dest = call_args(rest[end + 1..].trim_start_matches(','));
            let (var, leaf) = leaf_of(&lines, n, dest[0]);
            // each link or rename of the copy below: (line, the name it gets)
            let moves: Vec<(usize, String)> = lines
                .iter()
                .enumerate()
                .take((n + 30).min(lines.len()))
                .skip(n + 1)
                .filter_map(|(m, l)| {
                    let call = ["hard_link(", "symlink(", "rename("]
                        .iter()
                        .find_map(|c| l.find(c).map(|i| &l[i + c.len()..]))?;
                    let args = call_args(call);
                    let (first, second) = (args.first()?, args.get(1)?);
                    has_ident(first, &var).then(|| (m, leaf_of(&lines, m, second).1))
                })
                .collect();
            if leaf != util {
                // a copy renamed into place, by the utility's name, before it runs
                if !moves.iter().any(|(_, to)| to == util) {
                    found.push((n + 1, util.to_string(), leaf));
                }
                continue;
            }
            // the copy keeps the name: a link or rename of it to another
            for (m, to) in moves {
                if to != util {
                    found.push((m + 1, util.to_string(), to));
                }
            }
        }
        found
    }
}
