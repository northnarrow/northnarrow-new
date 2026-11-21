//! Lot 383: a test helper tells NorthNarrow's BPF programs by identity —
//! the ids of the agent's `bpf-own-ids` list, or our LSM programs' names —
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
use std::path::Path;
use std::process::Command;

use support::{repo_root, tracked_files};

const NAMES: &str = "deploy/lab/lib/our-lsm-programs.txt";
const HELPER: &str = "deploy/lab/lib/our-lsm.sh";

fn read(rel: &str) -> String {
    std::fs::read_to_string(repo_root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// The function name of every `#[lsm(…)]` program of the eBPF sources.
fn lsm_functions() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let dir = repo_root().join("agent-ebpf/src");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "rs"))
        .collect();
    files.sort();
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        let mut want = false;
        for line in text.lines() {
            let t = line.trim_start();
            if t.starts_with("#[lsm(") {
                want = true;
                continue;
            }
            if want {
                if let Some(rest) = t.split("fn ").nth(1).filter(|_| t.contains("fn ")) {
                    let name: String = rest
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                        .collect();
                    out.insert(name);
                    want = false;
                }
            }
        }
    }
    out
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
    let scanned = |f: &str| {
        (f.starts_with("agent/tests/")
            || f.starts_with("watchdog/tests/")
            || f.starts_with("crates/") && f.contains("/tests/")
            || f.starts_with("deploy/lab/")
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
    // by id: the listed ones, whatever their type
    let (rc, out) = helper(Some(LISTING), None, "our_progs_left 42 99");
    assert_eq!(rc, Some(0));
    assert_eq!(
        out,
        "42: kprobe  name udp_send_skb  tag 0011223344556679  gpl\n"
    );
    assert_eq!(
        helper(Some(LISTING), None, "our_progs_count"),
        (Some(0), "2\n".into())
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
    // no list of names, or one that names none
    assert_eq!(
        helper(
            Some(LISTING),
            Some(Path::new("/nonexistent/our-lsm-programs.txt")),
            "our_progs_count"
        ),
        (Some(2), "unknown\n".into())
    );
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
