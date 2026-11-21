//! Lot 383: a test helper tells NorthNarrow's BPF programs by identity —
//! the ids of the agent's `bpf-own-ids` list and our LSM programs' names —
//! never by counting every LSM program on the host.
//!
//! systemd 257 and newer (Debian 13, Ubuntu 26.04) keep a BPF-LSM program
//! of their own loaded for `RestrictFileSystems=` (`restrict_filesy`), held
//! by PID 1: no stop of NorthNarrow detaches it. The guard e2e teardown
//! (`agent/tests/privileged_e2e.rs`, `purge_pins_in_window`) waited for "no
//! LSM program" when its fixture had no list in hand, and the nightly of
//! 2026-11-21 failed seven guard tests on ubuntu2604 and debian13 after
//! they had passed ("LSM programs still loaded: 1"). Lot 377 fixed the
//! same class in install.sh and uninstall.sh, lot 374 in one test.
//!
//! The one list of names is `deploy/lab/lib/our-lsm-programs.txt`, held
//! here equal to agent-ebpf's `#[lsm]` functions; the Rust fixture
//! (`agent/tests/common/mod.rs`, `our_bpf`) includes it, the lab's shell
//! helper (`deploy/lab/lib/our-lsm.sh`) reads it. The ratchet below fails
//! on a test helper or a lab script that counts every LSM program again.

mod support;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use support::{repo_root, tracked_files};

const NAMES: &str = "deploy/lab/lib/our-lsm-programs.txt";
const HELPER: &str = "deploy/lab/lib/our-lsm.sh";

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// Every `.rs` file under `dir`, its subdirectories included (the review
/// of #590, P3-2: a flat `read_dir` of `agent-ebpf/src` did not see a
/// program in a module directory).
fn rs_files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut todo = vec![dir.to_path_buf()];
    while let Some(d) = todo.pop() {
        for e in std::fs::read_dir(&d)
            .unwrap_or_else(|e| panic!("{}: {e}", d.display()))
            .flatten()
        {
            let p = e.path();
            if p.is_dir() {
                todo.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// Whether `line` is an `lsm` program attribute, under any path to the
/// macro and with any spacing: `#[lsm(…)]`, `#[macros::lsm(…)]`,
/// `#[aya_ebpf::macros::lsm(…)]` (the review of #590, P3-2: only
/// `#[lsm(` was seen).
fn is_lsm_attribute(line: &str) -> bool {
    let t: String = line.chars().filter(|c| !c.is_whitespace()).collect();
    let Some(attr) = t.strip_prefix("#[") else {
        return false;
    };
    let path = &attr[..attr.find(['(', ']']).unwrap_or(attr.len())];
    path.rsplit("::").next() == Some("lsm")
}

/// The function name of every `lsm` program of one source file.
fn lsm_functions_in(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut want = false;
    for line in text.lines() {
        let t = line.trim_start();
        if is_lsm_attribute(t) {
            want = true;
        }
        if want {
            if let Some(rest) = t.split("fn ").nth(1).filter(|_| t.contains("fn ")) {
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                out.push(name);
                want = false;
            }
        }
    }
    out
}

/// The function name of every `lsm` program of the eBPF sources.
fn lsm_functions() -> BTreeSet<String> {
    rs_files_under(&repo_root().join("agent-ebpf/src"))
        .iter()
        .flat_map(|f| lsm_functions_in(&std::fs::read_to_string(f).unwrap()))
        .collect()
}

fn listed_names() -> BTreeSet<String> {
    read(NAMES)
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect()
}

#[test]
fn the_list_of_our_lsm_programs_is_the_ebpf_sources() {
    let src = lsm_functions();
    assert!(src.len() >= 60, "{src:?}");
    let listed = listed_names();
    let missing: Vec<_> = src.difference(&listed).collect();
    let stale: Vec<_> = listed.difference(&src).collect();
    assert!(
        missing.is_empty() && stale.is_empty(),
        "{NAMES} is not agent-ebpf's #[lsm] functions: missing {missing:?}, not in the source {stale:?}"
    );
}

/// The review of #590, P3-2, planted: a program in a module directory and
/// one whose attribute names the macro by its path were not in the list,
/// and the ratchet above stayed green.
#[test]
fn the_ratchet_sees_every_lsm_program_of_the_ebpf_sources() {
    let dir = std::env::temp_dir().join(format!("nn383-ebpf-src-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("planted/deeper")).unwrap();
    std::fs::write(dir.join("main.rs"), "mod planted;\n").unwrap();
    std::fs::write(
        dir.join("planted/mod.rs"),
        "#[lsm(hook = \"file_open\")]\npub fn planted_open(ctx: LsmContext) -> i32 { 0 }\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("planted/deeper/x.rs"),
        "#[lsm(hook = \"bprm_check_security\")]\npub fn planted_deeper(ctx: LsmContext) -> i32 { 0 }\n",
    )
    .unwrap();
    let files = rs_files_under(&dir);
    let found: BTreeSet<String> = files
        .iter()
        .flat_map(|f| lsm_functions_in(&std::fs::read_to_string(f).unwrap()))
        .collect();
    std::fs::remove_dir_all(&dir).ok();
    assert_eq!(files.len(), 3, "{files:?}");
    assert_eq!(
        found,
        ["planted_deeper", "planted_open"].map(String::from).into()
    );

    let planted = "\
#[aya_ebpf::macros::lsm(hook = \"file_open\")]
pub fn by_full_path(ctx: LsmContext) -> i32 { 0 }
#[macros::lsm(hook = \"task_kill\")]
fn by_module_path(ctx: LsmContext) -> i32 { 0 }
# [ lsm ( hook = \"inode_unlink\" ) ]
pub fn spaced(ctx: LsmContext) -> i32 { 0 }
#[lsm(hook = \"inode_rename\", sleepable)]
#[inline(never)]
pub fn with_another_attribute(ctx: LsmContext) -> i32 { 0 }
#[lsm(hook = \"path_chmod\")] pub fn on_one_line(ctx: LsmContext) -> i32 { 0 }
// #[lsm(hook = \"file_open\")] a comment
#[kprobe]
pub fn not_lsm(ctx: ProbeContext) -> u32 { 0 }
#[lsm_like(hook = \"x\")]
pub fn not_lsm_either(ctx: LsmContext) -> i32 { 0 }
";
    assert_eq!(
        lsm_functions_in(planted),
        [
            "by_full_path",
            "by_module_path",
            "spaced",
            "with_another_attribute",
            "on_one_line"
        ]
        .map(String::from)
    );
    assert!(!is_lsm_attribute(
        "#[cfg_attr(feature = \"x\", lsm(hook = \"y\"))]"
    ));
}

/// An alias of the macro (`use aya_ebpf::macros::lsm as hook;`) would
/// hide its programs from the scan above.
#[test]
fn the_lsm_macro_is_never_imported_under_another_name() {
    for f in rs_files_under(&repo_root().join("agent-ebpf/src")) {
        let text: String = std::fs::read_to_string(&f)
            .unwrap()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(!text.contains("lsm as "), "{}", f.display());
    }
}

#[test]
fn no_name_of_ours_is_systemds_lsm_program() {
    // as the kernel keeps them: 15 bytes
    let ours: BTreeSet<String> = listed_names()
        .iter()
        .map(|n| n.chars().take(15).collect())
        .collect();
    for systemd in [
        "restrict_filesy",
        "restrict_fs",
        "sd_fw_egress",
        "sd_devices",
    ] {
        assert!(!ours.contains(systemd), "{systemd}");
    }
}

/// What a helper that counts every LSM program on the host looks like.
fn counts_every_lsm_program(line: &str) -> bool {
    let squeezed: String = line.split_whitespace().collect::<Vec<_>>().join(" ");
    [
        "grep -c ' lsm '",
        "grep -c \" lsm \"",
        "grep -c ' lsm'",
        "grep -c \" lsm\"",
        "grep ' lsm ' | wc -l",
        "grep \" lsm \" | wc -l",
    ]
    .iter()
    .any(|p| squeezed.contains(p))
}

#[test]
fn no_test_helper_counts_every_lsm_program_on_the_host() {
    // the review of #590, P3-3: deploy/adversarial/ and the docs' scripts
    // were outside the scope, and one of them counted every LSM program
    let scanned = |f: &str| {
        (f.starts_with("agent/tests/")
            || f.starts_with("watchdog/tests/")
            || f.starts_with("crates/") && f.contains("/tests/")
            || f.starts_with("deploy/")
            || f.starts_with("docs/") && f.contains("/scripts/")
            || f.ends_with(".sh")
            || f.starts_with(".github/")
            || f.starts_with("xtask/"))
            && f != "xtask/tests/our_lsm_identity.rs"
    };
    let mut hits = Vec::new();
    let mut files = 0;
    for f in tracked_files().into_iter().filter(|f| scanned(f)) {
        let Ok(text) = std::fs::read_to_string(repo_root().join(&f)) else {
            continue;
        };
        files += 1;
        for (i, line) in text.lines().enumerate() {
            if counts_every_lsm_program(line) {
                hits.push(format!("{f}:{}: {}", i + 1, line.trim()));
            }
        }
    }
    assert!(files > 300, "scanned {files} files");
    assert!(
        hits.is_empty(),
        "these count every LSM program on the host, PID 1's included (systemd 257+ keeps one): \
         tell ours by id or by name ({HELPER}, or common::our_bpf in Rust):\n{}",
        hits.join("\n")
    );
}

#[test]
fn the_ratchet_sees_the_old_spellings() {
    for old in [
        r#"        [ "$(bpftool prog show 2>/dev/null | grep -c ' lsm ')" = 0 ] && exit 0"#,
        r#"    n=$(sudo bpftool prog show 2>/dev/null | grep -c " lsm ")"#,
        r#"lsm() { sudo bpftool prog show 2>/dev/null | grep -c " lsm " || true; }"#,
        r#"n=$(bpftool prog show | grep  " lsm "  | wc -l)"#,
    ] {
        assert!(counts_every_lsm_program(old), "{old}");
    }
    // the identity-based counts stay allowed
    for new in [
        r#"foreign_before=$(sudo bpftool prog show 2>/dev/null | grep " lsm " | grep -vcE "^(${own_ids// /|}x):" || true)"#,
        r#"for id in $own; do sudo bpftool prog show id "$id" 2>/dev/null | grep -q " lsm " && n=$((n + 1)); done"#,
        "lsm_programs() { our_progs_count; }",
    ] {
        assert!(!counts_every_lsm_program(new), "{new}");
    }
}

/// `deploy/lab/lib/our-lsm.sh` against a `bpftool prog show` listing:
/// a fake `bpftool` (and a `sudo` that runs its arguments) first in PATH.
fn helper(listing: Option<&str>, names: Option<&Path>, call: &str) -> (Option<i32>, String) {
    static RUN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "nn383-lsm-{}-{}",
        std::process::id(),
        RUN.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let listing_file = dir.join("listing");
    let bpftool = match listing {
        Some(l) => {
            std::fs::write(&listing_file, l).unwrap();
            format!("#!/bin/sh\ncat '{}'\n", listing_file.display())
        }
        None => "#!/bin/sh\necho 'Error: can not get next program' >&2\nexit 255\n".to_string(),
    };
    for (name, body) in [
        ("bpftool", bpftool.as_str()),
        ("sudo", "#!/bin/sh\nexec \"$@\"\n"),
    ] {
        let p = bin.join(name);
        std::fs::write(&p, body).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut cmd = Command::new("bash");
    cmd.arg("-c")
        .arg(format!(
            ". '{}'; {call}",
            repo_root().join(HELPER).display()
        ))
        .env(
            "PATH",
            format!("{}:{}", bin.display(), std::env::var("PATH").unwrap()),
        );
    if let Some(n) = names {
        cmd.env("NN_OUR_LSM_NAMES", n);
    }
    let out = cmd.output().expect("bash runs");
    std::fs::remove_dir_all(&dir).ok();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

/// systemd 259's program (Ubuntu 26.04) beside ours, a kprobe of ours,
/// another product's LSM program without a name, and a kprobe named like
/// one of our LSM programs (by name only LSM programs are ours).
const LISTING: &str = "\
12: lsm  name restrict_filesy  tag 9f8e7d6c5b4a3210  gpl
\tloaded_at 2026-11-21T08:00:00+0000  uid 0
\txlated 1000B  jited 600B  memlock 4096B  map_ids 3
40: lsm  name task_kill  tag 0011223344556677  gpl
41: lsm  name mount_guard_sb_  tag 0011223344556678  gpl
42: kprobe  name udp_send_skb  tag 0011223344556679  gpl
43: lsm  tag 001122334455667a  gpl
44: kprobe  name task_kill  tag 001122334455667b  gpl
";

#[cfg(unix)]
#[test]
fn the_lab_helper_never_counts_pid_ones_lsm_program() {
    // systemd's alone: nothing of ours, by name and by id
    let only_systemd = LISTING.lines().take(3).collect::<Vec<_>>().join("\n") + "\n";
    assert_eq!(
        helper(Some(&only_systemd), None, "our_progs_count"),
        (Some(0), "0\n".into())
    );
    assert_eq!(
        helper(Some(&only_systemd), None, "our_progs_count 40 41"),
        (Some(0), "0\n".into())
    );
}

#[cfg(unix)]
#[test]
fn the_lab_helper_counts_a_leftover_of_ours_by_id_or_by_name() {
    // by name: ours (15 bytes kept by the kernel), not systemd's, not a
    // nameless one, not a kprobe
    let (rc, out) = helper(Some(LISTING), None, "our_progs_left");
    assert_eq!(rc, Some(0));
    assert_eq!(
        out,
        "40: lsm  name task_kill  tag 0011223344556677  gpl\n\
         41: lsm  name mount_guard_sb_  tag 0011223344556678  gpl\n"
    );
    // by id: the listed ones, whatever their type — and ours by name too
    let (rc, out) = helper(Some(LISTING), None, "our_progs_left 42 99");
    assert_eq!(rc, Some(0));
    assert_eq!(
        out,
        "40: lsm  name task_kill  tag 0011223344556677  gpl\n\
         41: lsm  name mount_guard_sb_  tag 0011223344556678  gpl\n\
         42: kprobe  name udp_send_skb  tag 0011223344556679  gpl\n"
    );
    assert_eq!(
        helper(Some(LISTING), None, "our_progs_count"),
        (Some(0), "2\n".into())
    );
}

/// The review of #590, P3-1: with ids given, the names were skipped — a
/// program of ours outside the list (a run that never wrote it, an earlier
/// binary's leftover) counted as none left.
#[cfg(unix)]
#[test]
fn the_lab_helper_counts_a_leftover_of_ours_outside_the_ids() {
    let only_ours_by_name = "\
12: lsm  name restrict_filesy  tag 9f8e7d6c5b4a3210  gpl
40: lsm  name task_kill  tag 0011223344556677  gpl
";
    assert_eq!(
        helper(Some(only_ours_by_name), None, "our_progs_count 7 8 9"),
        (Some(0), "1\n".into())
    );
}

#[cfg(unix)]
#[test]
fn the_lab_helper_says_unknown_when_it_cannot_tell() {
    // bpftool fails: never "0 left"
    assert_eq!(
        helper(None, None, "our_progs_count"),
        (Some(2), "unknown\n".into())
    );
    assert_eq!(
        helper(None, None, "our_progs_count 40"),
        (Some(2), "unknown\n".into())
    );
    // no list of names, or one that names none — ids given or not
    for call in ["our_progs_count", "our_progs_count 40"] {
        assert_eq!(
            helper(
                Some(LISTING),
                Some(Path::new("/nonexistent/our-lsm-programs.txt")),
                call
            ),
            (Some(2), "unknown\n".into()),
            "{call}"
        );
    }
    let empty = std::env::temp_dir().join(format!("nn383-names-{}", std::process::id()));
    std::fs::write(&empty, "# no name\n\n").unwrap();
    let got = helper(Some(LISTING), Some(&empty), "our_progs_count");
    std::fs::remove_file(&empty).ok();
    assert_eq!(got, (Some(2), "unknown\n".into()));
}

#[test]
fn the_fixture_and_the_lab_read_the_one_list() {
    let common = read("agent/tests/common/mod.rs");
    assert!(
        common.contains("\"/deploy/lab/lib/our-lsm-programs.txt\""),
        "common::our_bpf includes {NAMES}"
    );
    let e2e = read("agent/tests/privileged_e2e.rs");
    assert!(e2e.contains("common::our_bpf::wait_ours_gone(&ids, PURGE_UNLOAD_TIMEOUT)"));
    for lab in [
        "deploy/lab/nn-lab.sh",
        "deploy/lab/pkg/pkg-check.sh",
        "deploy/lab/perf/perf-run.sh",
    ] {
        assert!(read(lab).contains("our-lsm.sh"), "{lab} uses {HELPER}");
    }
    // perf-run.sh runs from a flat copy: its helper and the names go with it
    let nn_lab = read("deploy/lab/nn-lab.sh");
    assert!(nn_lab.contains(
        "\"$REPO/deploy/lab/lib/our-lsm.sh\" \"$REPO/deploy/lab/lib/our-lsm-programs.txt\" \"$GUEST:nn-perf/\""
    ));
}
