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

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives one level below the repository root")
        .to_path_buf()
}

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

/// `(source, destination)` of each `cp`/`install` of a coreutils program
/// on `line` whose destination does not keep the program's name.
fn renamed_util_copies(line: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    let words: Vec<&str> = line
        .split(|c: char| c.is_whitespace() || c == ';' || c == '(' || c == ')' || c == '\'')
        .filter(|w| !w.is_empty())
        .collect();
    for (i, w) in words.iter().enumerate() {
        if *w != "cp" && *w != "install" {
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
        let Some(util) = src
            .strip_prefix("/usr/bin/")
            .or_else(|| src.strip_prefix("/bin/"))
        else {
            continue;
        };
        if !MULTICALL_UTILS.contains(&util) {
            continue;
        }
        let leaf = dst.trim_matches('"').rsplit('/').next().unwrap_or("");
        if leaf != util {
            found.push((src.to_string(), dst.to_string()));
        }
    }
    found
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
        for line in fs::read_to_string(f).unwrap().lines() {
            if line.trim_start().starts_with('#') {
                continue;
            }
            for (src, dst) in renamed_util_copies(line) {
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

/// Every `.rs` file under `dir`, `target/` skipped, sorted.
fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries {
        let p = e.unwrap().path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            rs_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
    out.sort();
}

/// The string literal of the last `join("…")` on `line`.
fn last_join(line: &str) -> Option<&str> {
    let at = line.rfind("join(\"")? + "join(\"".len();
    let end = line[at..].find('"')?;
    Some(&line[at..at + end])
}

/// `(line number, utility, destination leaf)` of each copy in `code` of a
/// coreutils program (`fs::copy("/bin/sleep", &var)`) to a path built by a
/// `let var = ….join("…")` just above, whose last component is not the
/// utility's name, and that is then run (`Command::new(&var)`) below — a
/// copy renamed into place before it runs is not one.
fn renamed_spawned_copies(code: &str) -> Vec<(usize, String, String)> {
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
        let var: String = rest[end + 1..]
            .trim_start_matches([',', ' ', '&'])
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if var.is_empty() {
            continue;
        }
        let built = lines[n.saturating_sub(8)..n]
            .iter()
            .rev()
            .find(|l| l.contains(&format!("let {var} = ")))
            .and_then(|l| last_join(l));
        let Some(dest) = built else {
            continue;
        };
        let leaf = dest.rsplit('/').next().unwrap_or(dest);
        let spawned = lines[n + 1..(n + 30).min(lines.len())].iter().any(|l| {
            l.contains(&format!("Command::new(&{var})"))
                || l.contains(&format!("Command::new({var})"))
        });
        if spawned && leaf != util {
            found.push((n + 1, util.to_string(), leaf.to_string()));
        }
    }
    found
}

/// Copies run under another name on purpose: only their exec is read (an
/// exec record, a barrier), never what the program does or how it exits.
const EXEC_ONLY_COPIES: &[&str] = &[
    "agent/tests/common/mod.rs: a copy of true named nn_barrier",
    "agent/tests/detection_rules_at_scale_privileged_e2e.rs: a copy of true named nnchain_quiet",
];

/// Lot 344 (named, item 9: #549's CI failure, its root cause): no test runs
/// a copy of a coreutils program under another name — on the hosted
/// runners' uutils the child printed "unknown program" and exited at once.
#[test]
fn no_test_runs_a_coreutils_copy_under_another_name() {
    let probe = "        let mal = tmp.path().join(\"mal\");\n        std::fs::copy(\"/bin/sleep\", &mal).unwrap();\n        let c = std::process::Command::new(&mal).arg(\"60\").spawn();\n";
    assert_eq!(
        renamed_spawned_copies(probe),
        vec![(2, "sleep".to_string(), "mal".to_string())]
    );
    let kept = "        let mal = tmp.path().join(\"mal\").join(\"sleep\");\n        std::fs::copy(\"/bin/sleep\", &mal).unwrap();\n        let c = std::process::Command::new(&mal).arg(\"60\").spawn();\n";
    assert!(renamed_spawned_copies(kept).is_empty());
    let mut files = Vec::new();
    for top in ["agent", "crates", "watchdog", "cli", "scan", "xtask/src"] {
        rs_files(&repo_root().join(top), &mut files);
    }
    assert!(files.len() > 100, "{} sources", files.len());
    let mut bad = Vec::new();
    for f in &files {
        let rel = f.strip_prefix(repo_root()).unwrap().display().to_string();
        for (n, util, leaf) in renamed_spawned_copies(&fs::read_to_string(f).unwrap()) {
            let entry = format!("{rel}: a copy of {util} named {leaf}");
            if !EXEC_ONLY_COPIES.contains(&entry.as_str()) {
                bad.push(format!("{entry} (line {n})"));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "a coreutils program run under another name exits at once on uutils (Ubuntu 26.04, \
         the hosted runners) — keep the name in a directory of its own: {bad:#?}"
    );
}
