//! The CI VM gate (Wave 4 Phase 2.1, lab PR 227). `.github/workflows/lab-vm.yml`
//! runs `deploy/lab/nn-lab.sh test-ignored` in one KVM guest per matrix entry
//! on GitHub-hosted runners, nn-lab.sh has a CI mode for it (NN_LAB_CI=1), and
//! `cargo xtask gate-summary` / `gate-report` judge and report the run, with
//! the expected failures of `deploy/lab/expected-failures.tsv` shown, never
//! dropped. The workflow cannot run here: these tests check what it says —
//! the trees that start it, the matrix, the token and the pins, the policy
//! (informational on a pull request, the gate at night, "skipped: no KVM"),
//! the bounds, KVM, the image cache, the order of the steps and the evidence
//! it keeps — and run what can run locally. Offline: committed files, `bash`
//! (`-n` on the lab scripts and the workflow's steps; nn-lab.sh's CI
//! switches), `ssh -G`, the xtask binary on synthetic logs, the download
//! self-test when GnuPG is present. No guest, nothing privileged, nothing written outside the
//! target directory (the self-test's own temporary directory aside).

use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};

mod support;

const WORKFLOW: &str = ".github/workflows/lab-vm.yml";
const NN_LAB: &str = "deploy/lab/nn-lab.sh";
const EXPECTED: &str = "deploy/lab/expected-failures.tsv";
const XTASK: &str = env!("CARGO_BIN_EXE_xtask");

/// The guests a pull request runs, and those the nightly and a dispatch run.
const PR_GUESTS: [&str; 2] = ["ubuntu2404", "ubuntu2204"];
const NIGHTLY_GUESTS: [&str; 5] = [
    "ubuntu2404",
    "ubuntu2204",
    "debian12",
    "debian13",
    "ubuntu2604",
];

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

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn case_dir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("lab-ci")
        .join(name);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn have(tool: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool}"))
        .stdout(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

type Yaml = serde_yaml_ng::Value;

fn workflow() -> Yaml {
    serde_yaml_ng::from_str(&read(WORKFLOW)).unwrap_or_else(|e| panic!("{WORKFLOW}: {e}"))
}

fn str_of<'a>(v: &'a Yaml, key: &str) -> Option<&'a str> {
    v.get(key).and_then(|x| x.as_str())
}

/// The one job of the workflow.
fn job() -> Yaml {
    let wf = workflow();
    let jobs = wf
        .get("jobs")
        .and_then(|j| j.as_mapping())
        .expect("lab-vm.yml has jobs");
    assert_eq!(
        jobs.len(),
        1,
        "{WORKFLOW}: one job, one guest per matrix entry"
    );
    jobs.values().next().unwrap().clone()
}

fn steps() -> Vec<Yaml> {
    job()
        .get("steps")
        .and_then(|s| s.as_sequence())
        .cloned()
        .expect("the job has steps")
}

fn run_of(step: &Yaml) -> &str {
    str_of(step, "run").unwrap_or("")
}

/// The index of the one step whose `run:` contains `needle`.
fn step_running(steps: &[Yaml], needle: &str) -> usize {
    let found: Vec<usize> = steps
        .iter()
        .enumerate()
        .filter(|(_, s)| run_of(s).contains(needle))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        found.len(),
        1,
        "{WORKFLOW}: one step runs `{needle}`, found {found:?}"
    );
    found[0]
}

fn step_using(steps: &[Yaml], action: &str) -> Vec<usize> {
    steps
        .iter()
        .enumerate()
        .filter(|(_, s)| str_of(s, "uses").is_some_and(|u| u.starts_with(&format!("{action}@"))))
        .map(|(i, _)| i)
        .collect()
}

// ── which pull requests start it ──────────────────────────────────────────

/// `a/b/../c` → `a/c`; None when it leaves the repository.
fn normalize(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    Some(out)
}

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
}

/// The repository paths the privileged suites are built or run from: the
/// workspace members (`cargo metadata`, lab PR 239), the eBPF crate xtask
/// builds, the `[patch]` paths, every file a member embeds or reads from
/// outside itself (`include_str!`/`include_bytes!` relative to the file,
/// or `env!("NN_REPO_ROOT")` and the path after it, R00), the top-level
/// trees the members' code and tests read (`.join("configs")`,
/// `"/../configs"`; xtask's aside), the toolchain and the lockfile, the lab
/// script and the workflow.
fn trees_the_suites_need() -> BTreeSet<String> {
    let root = repo_root();
    let cargo = read("Cargo.toml");
    let members: Vec<String> = support::members().into_iter().map(|m| m.dir).collect();
    let mut need: BTreeSet<String> = members.iter().cloned().collect();
    need.insert("agent-ebpf".to_string());
    // the path dependencies of a `[patch.*]` section (none today)
    let mut in_patch = false;
    for line in cargo.lines() {
        let t = line.trim_start();
        if t.starts_with('[') {
            in_patch = t.starts_with("[patch.");
        } else if in_patch {
            if let Some(rest) = line.split("path = \"").nth(1) {
                need.insert(rest.split('"').next().unwrap().to_string());
            }
        }
    }
    for m in &members {
        let krate = root.join(m);
        let mut files = Vec::new();
        rs_files(&krate, &mut files);
        for f in files {
            let src = fs::read_to_string(&f).unwrap();
            for marker in ["include_str!(\"", "include_bytes!(\""] {
                for piece in src.split(marker).skip(1) {
                    let rel = piece.split('"').next().unwrap();
                    let target = normalize(&f.parent().unwrap().join(rel)).unwrap();
                    if !target.starts_with(&krate) {
                        let r = target.strip_prefix(&root).unwrap().display().to_string();
                        need.insert(r);
                    }
                }
            }
            // `concat!(env!("NN_REPO_ROOT"), "/configs/…")`, over lines too
            for piece in src.split("env!(\"NN_REPO_ROOT\")").skip(1) {
                let rest = piece.trim_start_matches(|c: char| c.is_whitespace() || c == ',');
                let Some(lit) = rest.strip_prefix("\"/") else {
                    continue;
                };
                let rel = lit.split('"').next().unwrap().trim_end_matches('/');
                let target = normalize(Path::new(rel)).unwrap();
                if !rel.is_empty() && !target.starts_with(m) {
                    need.insert(target.display().to_string());
                }
            }
        }
    }
    let top: BTreeSet<String> = fs::read_dir(&root)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .filter(|n| !n.starts_with('.') && n != "target")
        .collect();
    // xtask's own reads stay out: its tests run on the host (the `test`
    // job), never in a guest
    for m in members.iter().filter(|m| *m != "xtask") {
        let mut files = Vec::new();
        rs_files(&root.join(m), &mut files);
        for f in files {
            let src = fs::read_to_string(&f).unwrap();
            for t in &top {
                if src.contains(&format!(".join(\"{t}\")"))
                    || src.contains(&format!(".join(\"{t}/"))
                    || src.contains(&format!("\"/../{t}\""))
                    || src.contains(&format!("\"/../{t}/"))
                {
                    need.insert(t.clone());
                }
            }
        }
    }
    for f in [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        ".cargo/config.toml",
        NN_LAB,
        WORKFLOW,
    ] {
        need.insert(f.to_string());
    }
    // the trees the gate was asked to cover, whatever the scan finds
    for t in ["agent", "agent-ebpf", "common", "watchdog", "deploy"] {
        need.insert(t.to_string());
    }
    need
}

fn pr_paths() -> Vec<String> {
    let wf = workflow();
    let pr = wf
        .get("on")
        .and_then(|o| o.get("pull_request"))
        .expect("lab-vm.yml runs on pull_request");
    assert!(
        pr.get("paths-ignore").is_none(),
        "{WORKFLOW}: paths, not paths-ignore"
    );
    pr.get("paths")
        .and_then(|p| p.as_sequence())
        .expect("pull_request has paths")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

/// A GitHub path filter of the two shapes used here: `dir/**` or a file.
fn filter_matches(filter: &str, path: &str) -> bool {
    match filter.strip_suffix("/**") {
        Some(dir) => path == dir || path.starts_with(&format!("{dir}/")),
        None => filter == path,
    }
}

/// A pull request that touches anything the privileged suites are built or
/// run from starts the gate; a filter list written by hand would miss the
/// next embedded file or the next crate. The list is derived from the
/// repository (members, include_str!, the trees the tests read) and every
/// entry must be covered; no negation can take one back.
#[test]
fn lab_vm_runs_on_every_tree_the_privileged_suites_are_built_from() {
    let paths = pr_paths();
    assert!(
        paths.iter().all(|p| !p.starts_with('!')),
        "{WORKFLOW}: no negated path filter: {paths:?}"
    );
    for p in &paths {
        assert!(
            p.ends_with("/**") || !p.contains('*'),
            "{WORKFLOW}: `{p}`: `dir/**` or a file"
        );
        let base = p.trim_end_matches("/**");
        assert!(
            repo_root().join(base).exists(),
            "{WORKFLOW}: the filter `{p}` names nothing in the repository"
        );
    }
    let need = trees_the_suites_need();
    assert!(need.len() > 15, "{need:?}");
    let missing: Vec<&String> = need
        .iter()
        .filter(|n| !paths.iter().any(|f| filter_matches(f, n)))
        .collect();
    assert!(
        missing.is_empty(),
        "{WORKFLOW}: no path filter covers {missing:?} (the privileged suites are built or run from them)"
    );
    // and the scan found what the suites are known to embed or read
    for known in [
        "configs",
        "deploy/systemd/northnarrow-agent.service",
        "docs/operator/COMBAT_RECOVERY.md",
    ] {
        assert!(need.contains(known), "the scan lost `{known}`: {need:?}");
    }
}

/// The two JSON lists of the matrix expression: (pull_request, otherwise).
fn matrix_lists() -> (Vec<String>, Vec<String>) {
    let j = job();
    let expr = j
        .get("strategy")
        .and_then(|s| s.get("matrix"))
        .and_then(|m| str_of(m, "distro"))
        .expect("strategy.matrix.distro is an expression")
        .to_string();
    let lists: Vec<Vec<String>> = expr
        .split('\'')
        .filter(|p| p.trim_start().starts_with('['))
        .map(|p| serde_json::from_str(p).unwrap_or_else(|e| panic!("{p}: {e}")))
        .collect();
    assert_eq!(lists.len(), 2, "{expr}");
    let pr_first = expr
        .find("github.event_name == 'pull_request' &&")
        .expect(&expr);
    let first_list = expr.find("'[").unwrap();
    assert!(
        pr_first < first_list,
        "the first list is the pull request's: {expr}"
    );
    assert!(expr.contains("fromJSON("), "{expr}");
    (lists[0].clone(), lists[1].clone())
}

/// Ubuntu 24.04 and 22.04 on a pull request; the lab's four guests and
/// Ubuntu 26.04 (lab PR 229: the runners' release, uutils coreutils) at
/// night and on a dispatch; nothing else starts it. Every guest is one nn-lab.sh
/// knows, one job each, and a failing guest does not cancel the others.
#[test]
fn lab_vm_matrix_two_ubuntu_kernels_on_prs_five_guests_nightly() {
    let (pr, nightly) = matrix_lists();
    assert_eq!(pr, PR_GUESTS);
    assert_eq!(nightly, NIGHTLY_GUESTS);
    let nn_lab = read(NN_LAB);
    for d in &nightly {
        assert!(
            nn_lab.contains(&format!("\n    {d})\n")),
            "{d}: not a guest of {NN_LAB}"
        );
    }
    let wf = workflow();
    let on = wf.get("on").and_then(|o| o.as_mapping()).expect("on:");
    let triggers: BTreeSet<&str> = on.keys().filter_map(|k| k.as_str()).collect();
    assert_eq!(
        triggers,
        BTreeSet::from(["pull_request", "schedule", "workflow_dispatch"])
    );
    let pr_on = wf.get("on").unwrap().get("pull_request").unwrap();
    assert_eq!(
        pr_on
            .get("branches")
            .and_then(|b| b.as_sequence())
            .map(|b| b.len()),
        Some(1)
    );
    assert!(wf
        .get("on")
        .unwrap()
        .get("schedule")
        .and_then(|s| s.as_sequence())
        .is_some_and(|s| s.iter().any(|e| str_of(e, "cron").is_some())));
    let j = job();
    assert_eq!(str_of(&j, "runs-on"), Some("ubuntu-24.04"));
    assert_eq!(
        j.get("strategy")
            .and_then(|s| s.get("fail-fast"))
            .and_then(|f| f.as_bool()),
        Some(false)
    );
    let env = j.get("env").expect("job env");
    assert_eq!(str_of(env, "NN_LAB_CI"), Some("1"));
    assert_eq!(str_of(env, "NN_LAB_ACCEL"), Some("kvm"));
    assert_eq!(str_of(env, "NN_LAB_DISTRO"), Some("${{ matrix.distro }}"));
}

/// `owner/repo@<40 hex> # vX.Y.Z` of every `uses:` line.
fn uses_lines(text: &str) -> Vec<(String, String, String)> {
    text.lines()
        .filter_map(|l| {
            let t = l.trim_start().trim_start_matches("- ").trim_start();
            let rest = t.strip_prefix("uses:")?.trim();
            let (value, comment) = rest.split_once(" # ").unwrap_or((rest, ""));
            let (name, sha) = value.split_once('@').unwrap_or((value, ""));
            Some((
                name.to_string(),
                sha.to_string(),
                comment.trim().to_string(),
            ))
        })
        .collect()
}

/// External audit SUP-002, SUP-003, SUP-004 for this workflow: a read-only
/// token and nothing more, never handed to a step or left in .git/config;
/// every action pinned by commit SHA with its version, at the SHA the
/// repository's other workflows pin (actions/cache/restore and /save are
/// actions/cache's); and after the host build of the dependency tree, the
/// credential check of release.yml, before a guest gets anything. (Every
/// cargo call being --locked is supply_chain.rs's, for every workflow.)
#[test]
fn lab_vm_is_least_privilege_and_pinned() {
    let wf = workflow();
    let perms = wf
        .get("permissions")
        .and_then(|p| p.as_mapping())
        .expect("top-level permissions");
    assert_eq!(perms.len(), 1, "{perms:?}");
    assert_eq!(
        str_of(wf.get("permissions").unwrap(), "contents"),
        Some("read")
    );
    assert!(
        job().get("permissions").is_none(),
        "the job asks for nothing more"
    );

    let text = read(WORKFLOW);
    let code: String = text
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    for banned in [
        "secrets.",
        "github.token",
        "GITHUB_TOKEN",
        "id-token",
        "write-all",
    ] {
        assert!(!code.contains(banned), "{WORKFLOW}: `{banned}`");
    }

    let mut others = String::new();
    for f in fs::read_dir(repo_root().join(".github/workflows")).unwrap() {
        let p = f.unwrap().path();
        if p.file_name().is_some_and(|n| n != "lab-vm.yml") {
            others.push_str(&fs::read_to_string(&p).unwrap());
        }
    }
    let pinned_elsewhere: BTreeSet<(String, String)> = uses_lines(&others)
        .into_iter()
        .map(|(n, s, _)| (n, s))
        .collect();
    let uses = uses_lines(&text);
    assert!(uses.len() >= 5, "{uses:?}");
    for (name, sha, comment) in &uses {
        assert!(
            sha.len() == 40
                && sha
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "{name}: pinned by a 40-hex commit SHA, not `{sha}`"
        );
        let v = comment.strip_prefix('v').unwrap_or("");
        assert!(
            v.split('.').count() == 3 && v.split('.').all(|p| p.parse::<u32>().is_ok()),
            "{name}@{sha}: `# vX.Y.Z` comment, not `{comment}`"
        );
        let base: String = name.splitn(3, '/').take(2).collect::<Vec<_>>().join("/");
        assert!(
            pinned_elsewhere.contains(&(base.clone(), sha.clone())),
            "{name}@{sha}: not the SHA the other workflows pin for {base}"
        );
    }

    let steps = steps();
    for i in step_using(&steps, "actions/checkout") {
        let persist = steps[i]
            .get("with")
            .and_then(|w| w.get("persist-credentials"));
        assert_eq!(persist.and_then(|p| p.as_bool()), Some(false));
    }
    let host = step_running(&steps, "cargo --locked xtask build-ebpf --locked");
    let check = step_running(&steps, "extraheader");
    assert!(run_of(&steps[check]).contains("ACTIONS_ID_TOKEN_REQUEST_URL"));
    let up = step_running(&steps, "deploy/lab/nn-lab.sh up");
    assert!(
        host < check && check < up,
        "the credential check follows the host build, before the guest"
    );
}

/// Hosted jobs stop at 6 h: the job has a bound below it, and every step
/// that builds, boots or waits has its own, so one that hangs leaves time
/// for the summary and the evidence. A newer push supersedes a pull
/// request's run; the nightly is never cancelled.
#[test]
fn lab_vm_bounds_every_step_and_the_job() {
    let j = job();
    let t = j
        .get("timeout-minutes")
        .and_then(|t| t.as_u64())
        .expect("job timeout-minutes");
    assert!((60..360).contains(&t), "job timeout {t}");
    let steps = steps();
    let mut sum = 0;
    for s in &steps {
        let run = run_of(s);
        if run.contains("nn-lab.sh") || run.contains("cargo ") || run.contains("apt-get") {
            let st = s
                .get("timeout-minutes")
                .and_then(|t| t.as_u64())
                .unwrap_or_else(|| {
                    panic!(
                        "{WORKFLOW}: no timeout-minutes on `{}`",
                        str_of(s, "name").unwrap_or(run)
                    )
                });
            assert!(st < t, "a step bound {st} not below the job's {t}");
            sum += st;
        }
    }
    assert!(sum > 0);
    let wf = workflow();
    let c = wf.get("concurrency").expect("concurrency");
    let group = str_of(c, "group").unwrap();
    assert!(
        group.contains("github.event.pull_request.number"),
        "{group}"
    );
    assert!(group.contains("github.event_name"), "{group}");
    let cancel = str_of(c, "cancel-in-progress").unwrap();
    assert!(
        cancel.contains("github.event_name == 'pull_request'"),
        "{cancel}"
    );
}

/// /dev/kvm opened the way GitHub documents (a udev rule), its use checked
/// before anything else needs it, the documentation cited; QEMU and the
/// image tools installed.
#[test]
fn lab_vm_opens_kvm_the_documented_way_before_the_guest() {
    let steps = steps();
    let kvm = step_running(&steps, "/etc/udev/rules.d/99-kvm4all.rules");
    let run = run_of(&steps[kvm]);
    for want in [
        r#"KERNEL=="kvm", GROUP="kvm", MODE="0666", OPTIONS+="static_node=kvm""#,
        "udevadm control --reload-rules",
        "udevadm trigger --name-match=kvm",
        "-w /dev/kvm",
        "available=true",
    ] {
        assert!(run.contains(want), "the KVM step lacks `{want}`:\n{run}");
    }
    let text = read(WORKFLOW);
    for cite in [
        "https://docs.github.com/en/actions/reference/runners/github-hosted-runners",
        "https://github.blog/changelog/2023-02-23-hardware-accelerated-android-virtualization",
        "https://github.blog/changelog/2024-04-02-github-actions-hardware-accelerated-android-virtualization",
    ] {
        assert!(text.contains(cite), "{WORKFLOW}: cite {cite}");
    }
    let apt = step_running(&steps, "apt-get install");
    for pkg in [
        "qemu-system-x86",
        "qemu-utils",
        "cloud-image-utils",
        "gpgv",
        "rsync",
    ] {
        assert!(run_of(&steps[apt]).contains(pkg), "{pkg} not installed");
    }
    let image = step_running(&steps, "nn-lab.sh image-info");
    let up = step_running(&steps, "deploy/lab/nn-lab.sh up");
    assert!(kvm < apt && apt < image && image < up);
}

/// The agreed policy: on a pull request the job is informational (a
/// workflow of its own, `continue-on-error`, never a required check, which
/// is the repository's setting, not this file's); the nightly and a dispatch
/// are the gate. A runner without KVM boots nothing and says "skipped: no
/// KVM" in the job summary, an annotation and the artefact: a pass on a pull
/// request, a failure on the nightly and a dispatch. Every step after the
/// KVM check depends on it; the summary does not run after a skip (that
/// step wrote it) and the evidence is uploaded either way. No
/// `pull_request_target`: a fork's pull request runs with the read-only
/// token and no secret.
#[test]
fn lab_vm_informs_on_pull_requests_and_gates_the_nightly() {
    let j = job();
    assert_eq!(
        str_of(&j, "continue-on-error"),
        Some("${{ github.event_name == 'pull_request' }}")
    );
    // the comments name it to say it is not used; the YAML must not
    let code: String = read(WORKFLOW)
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    for banned in ["pull_request_target", "workflow_run"] {
        assert!(!code.contains(banned), "{WORKFLOW}: `{banned}`");
    }
    let wf = workflow();
    let on = wf.get("on").and_then(|o| o.as_mapping()).expect("on:");
    assert!(on.keys().all(|k| k.as_str().is_some_and(|k| [
        "pull_request",
        "schedule",
        "workflow_dispatch"
    ]
    .contains(&k))));
    let steps = steps();
    let kvm = step_running(&steps, "/etc/udev/rules.d/99-kvm4all.rules");
    assert_eq!(str_of(&steps[kvm], "id"), Some("kvm"));
    assert!(
        str_of(&steps[kvm], "if").is_none(),
        "the KVM check always runs"
    );
    let run = run_of(&steps[kvm]);
    let skip = run
        .find("available=false")
        .expect("the KVM check reports no KVM");
    let (found, missing) = run.split_at(skip);
    assert!(found.contains("available=true") && found.contains("exit 0"));
    for want in [
        "skipped: no KVM",
        "$GITHUB_STEP_SUMMARY",
        "$GATE_OUT/skipped-no-kvm.txt",
        "::warning title=lab VM gate skipped: no KVM::",
        "::error title=lab VM gate skipped: no KVM::",
    ] {
        assert!(missing.contains(want), "the no-KVM branch lacks `{want}`");
    }
    let pr = missing
        .find("if [ \"$GITHUB_EVENT_NAME\" = pull_request ]; then")
        .expect("the no-KVM branch tells a pull request apart");
    let rest = &missing[pr..];
    let warn = rest.find("::warning").unwrap();
    let pass = rest.find("exit 0").unwrap();
    let error = rest.find("::error").unwrap();
    assert!(
        warn < pass && pass < error && rest[error..].contains("exit 1"),
        "no KVM: a pass on a pull request, a failure otherwise:\n{rest}"
    );
    // the KVM check comes before anything that costs time
    let free = steps
        .iter()
        .position(|s| run_of(s).contains("sudo rm -rf /usr/share/dotnet"))
        .expect("the disk step");
    assert!(kvm < free);
    let summary = step_running(&steps, "xtask gate-summary");
    let upload = step_using(&steps, "actions/upload-artifact")[0];
    for (i, s) in steps.iter().enumerate().skip(kvm + 1) {
        let cond = str_of(s, "if").unwrap_or("");
        let name = str_of(s, "name").unwrap_or("");
        if i == summary {
            assert_eq!(cond, "always() && steps.kvm.outputs.available != 'false'");
        } else if i == upload {
            assert_eq!(cond, "always()");
        } else {
            assert!(
                cond.starts_with("steps.kvm.outputs.available == 'true'"),
                "step {i} `{name}` runs without KVM: `if: {cond}`"
            );
        }
    }
}

/// The base image is cached under the digest the vendor's list gives now,
/// never restored from another key, checked against that list again once
/// restored (fetch-image), and saved only by main's runs and only when what
/// was verified is the image the key names.
#[test]
fn lab_vm_caches_only_images_it_verified() {
    let steps = steps();
    for action in [
        "actions/cache",
        "actions/cache/restore",
        "actions/cache/save",
    ] {
        for i in step_using(&steps, action) {
            assert!(
                steps[i]
                    .get("with")
                    .and_then(|w| w.get("restore-keys"))
                    .is_none(),
                "{WORKFLOW}: no restore-keys ({action})"
            );
        }
    }
    let image = step_running(&steps, "nn-lab.sh image-info");
    assert_eq!(str_of(&steps[image], "id"), Some("image"));
    assert!(run_of(&steps[image]).contains("$GITHUB_OUTPUT"));
    let restore = step_using(&steps, "actions/cache/restore");
    let save = step_using(&steps, "actions/cache/save");
    assert_eq!((restore.len(), save.len()), (1, 1));
    let (restore, save) = (restore[0], save[0]);
    let key = |i: usize| {
        str_of(steps[i].get("with").unwrap(), "key")
            .unwrap()
            .to_string()
    };
    let path = |i: usize| {
        str_of(steps[i].get("with").unwrap(), "path")
            .unwrap()
            .to_string()
    };
    assert_eq!(key(restore), key(save));
    for part in [
        "matrix.distro",
        "steps.image.outputs.algo",
        "steps.image.outputs.digest",
    ] {
        assert!(key(restore).contains(part), "{}", key(restore));
    }
    assert_eq!(path(restore), "${{ steps.image.outputs.path }}");
    assert_eq!(path(save), path(restore));
    let fetch = step_running(&steps, "nn-lab.sh fetch-image");
    assert_eq!(str_of(&steps[fetch], "id"), Some("fetch"));
    let up = step_running(&steps, "deploy/lab/nn-lab.sh up");
    assert!(image < restore && restore < fetch && fetch < save && save < up);
    let cond = str_of(&steps[save], "if").unwrap();
    for want in [
        "github.ref == 'refs/heads/main'",
        "steps.image-cache.outputs.cache-hit != 'true'",
        "steps.fetch.outputs.digest == steps.image.outputs.digest",
    ] {
        assert!(cond.contains(want), "save condition lacks `{want}`: {cond}");
    }
    let keys = step_using(&steps, "actions/cache");
    assert_eq!(keys.len(), 1);
    assert!(key(keys[0]).contains("hashFiles('deploy/lab/lib/verify-download.sh')"));
    assert!(
        keys[0] < image,
        "the pinned key is restored before the list is checked"
    );
}

/// up → sync → build → install → test-ignored, one step each; the gate's
/// verdict is the summary step's (always run, every earlier step's outcome
/// passed to it), and the evidence is uploaded whatever happened, last.
#[test]
fn lab_vm_runs_the_gate_in_order_and_keeps_its_evidence() {
    let steps = steps();
    let order: Vec<usize> = ["up", "sync", "build", "install", "test-ignored"]
        .iter()
        .map(|c| step_running(&steps, &format!("deploy/lab/nn-lab.sh {c}")))
        .collect();
    assert!(order.windows(2).all(|w| w[0] < w[1]), "{order:?}");
    let gate = run_of(&steps[order[4]]);
    for want in [
        "tee \"$GATE_OUT/gate.log\"",
        "PIPESTATUS[0]",
        "gate.rc",
        "uname -r",
        "exit 0",
    ] {
        assert!(gate.contains(want), "test-ignored step lacks `{want}`");
    }
    let summary = step_running(&steps, "xtask gate-summary");
    assert!(summary > order[4]);
    let s = &steps[summary];
    assert_eq!(
        str_of(s, "if"),
        Some("always() && steps.kvm.outputs.available != 'false'")
    );
    let run = run_of(s);
    for want in [
        "cargo --locked xtask gate-summary --locked",
        "--distro \"$NN_LAB_DISTRO\"",
        "--json \"$GATE_OUT/gate-summary.json\"",
        "$GITHUB_STEP_SUMMARY",
        "exit \"$status\"",
        "serial.log",
    ] {
        assert!(run.contains(want), "summary step lacks `{want}`");
    }
    let outcomes = str_of(s.get("env").unwrap(), "OUTCOMES").unwrap();
    for (i, st) in steps.iter().enumerate().take(summary) {
        if let (Some(id), Some(_)) = (str_of(st, "id"), st.get("run")) {
            assert!(
                outcomes.contains(&format!("=${{{{ steps.{id}.outcome }}}}")),
                "step {i} `{id}`: its outcome is not passed to gate-summary"
            );
        }
    }
    let upload = step_using(&steps, "actions/upload-artifact");
    assert_eq!(upload, vec![steps.len() - 1], "the upload is the last step");
    let u = &steps[upload[0]];
    assert_eq!(str_of(u, "if"), Some("always()"));
    let with = u.get("with").unwrap();
    assert!(str_of(with, "name")
        .unwrap()
        .contains("${{ matrix.distro }}"));
    assert_eq!(str_of(with, "path"), Some("${{ env.GATE_OUT }}/"));
    // the guest's user-data and seed (its private host key) stay on the runner
    for (i, st) in steps.iter().enumerate() {
        let r = run_of(st);
        assert!(
            !r.contains("user-data") && !r.contains("seed.iso"),
            "step {i} touches the guest's seed"
        );
    }
}

// ── the scripts parse ─────────────────────────────────────────────────────

fn sh_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            sh_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "sh") {
            out.push(p);
        }
    }
}

/// `bash -n` on every lab script and on every `run:` of the workflow (its
/// `${{ … }}` expressions replaced by a word).
#[test]
fn lab_scripts_and_the_workflow_steps_parse() {
    let mut files = Vec::new();
    sh_files(&repo_root().join("deploy/lab"), &mut files);
    files.sort();
    assert!(files.len() >= 10, "{files:?}");
    for f in &files {
        let out = Command::new("bash").arg("-n").arg(f).output().unwrap();
        assert!(out.status.success(), "{}: {}", f.display(), text(&out));
    }
    let dir = case_dir("steps");
    for (i, s) in steps().iter().enumerate() {
        let Some(run) = str_of(s, "run") else {
            continue;
        };
        let mut script = String::new();
        let mut rest = run;
        while let Some(at) = rest.find("${{") {
            script.push_str(&rest[..at]);
            let end = rest[at..].find("}}").expect("closed expression") + at + 2;
            script.push_str("EXPR");
            rest = &rest[end..];
        }
        script.push_str(rest);
        let f = dir.join(format!("step-{i}.sh"));
        fs::write(&f, &script).unwrap();
        let out = Command::new("bash").arg("-n").arg(&f).output().unwrap();
        assert!(out.status.success(), "step {i}: {}\n{script}", text(&out));
    }
}

// ── nn-lab.sh's CI mode ───────────────────────────────────────────────────

fn nn_lab(args: &[&str], env: &[(&str, &str)], name: &str) -> Output {
    let home = case_dir(name);
    let mut cmd = Command::new("bash");
    cmd.arg(repo_root().join(NN_LAB))
        .args(args)
        .env("HOME", &home)
        .env("NN_LAB_DIR", home.join("lab"))
        .env_remove("NN_LAB_DISTRO")
        .env_remove("NN_LAB_ACCEL")
        .env_remove("NN_LAB_LOCKDOWN")
        .env_remove("NN_LAB_CI")
        .stdin(Stdio::null());
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

/// CI mode is NN_LAB_CI=1 only (GitHub's own CI=true changes nothing), and
/// it runs a KVM guest or nothing: whpx and tcg are refused before anything
/// runs (exit 2, the configuration error status), as is any other value.
#[test]
fn nn_lab_ci_mode_is_opt_in_and_kvm_only() {
    let ok = nn_lab(&["help"], &[("NN_LAB_CI", "1")], "ci-help");
    assert!(ok.status.success(), "{}", text(&ok));
    assert!(String::from_utf8_lossy(&ok.stdout).contains("NN_LAB_CI=1"));
    for accel in ["whpx", "tcg"] {
        let out = nn_lab(
            &["help"],
            &[("NN_LAB_CI", "1"), ("NN_LAB_ACCEL", accel)],
            &format!("ci-{accel}"),
        );
        assert_eq!(out.status.code(), Some(2), "{accel}: {}", text(&out));
        assert!(
            text(&out).contains("NN_LAB_CI=1 runs the guest under KVM only"),
            "{}",
            text(&out)
        );
    }
    for bad in ["yes", "true", "2"] {
        let out = nn_lab(&["help"], &[("NN_LAB_CI", bad)], "ci-bad");
        assert_eq!(out.status.code(), Some(2), "NN_LAB_CI={bad}");
        assert!(text(&out).contains("unknown NN_LAB_CI"));
    }
    // the lab's whpx stays as it was without NN_LAB_CI, CI=true or not
    let lab = nn_lab(
        &["help"],
        &[("NN_LAB_ACCEL", "whpx"), ("CI", "true")],
        "lab-whpx",
    );
    assert!(lab.status.success(), "{}", text(&lab));
    assert!(!text(&lab).contains("runs the guest under KVM only"));
}

/// The ssh options block, run with or without CI mode, and `ssh -G` over it.
fn ssh_config(ci: Option<&str>, name: &str) -> String {
    let dir = case_dir(name);
    let text = read(NN_LAB);
    let start = text.find("# >>> ssh-options").unwrap();
    let end = text.find("# <<< ssh-options").unwrap();
    let block = &text[start..end];
    fs::write(dir.join("id_ed25519"), "").unwrap();
    let script = format!(
        "set -euo pipefail\nlog() {{ :; }}\ndie() {{ exit 1; }}\n{}LAB_DIR={lab:?}; ROOT_LAB_DIR=$LAB_DIR; KEY=\"$LAB_DIR/id_ed25519\"; GUEST_NAME=ubuntu2404; SSH_PORT=2322\n{block}\nexec ssh -G \"${{SSH_OPTS[@]}}\" nn@127.0.0.1\n",
        ci.map(|c| format!("CI_MODE={c}\n")).unwrap_or_default(),
        lab = dir.display().to_string(),
    );
    let out = Command::new("bash")
        .arg("-c")
        .arg(&script)
        .env("CI", "true")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", self::text(&out));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// In CI mode no ssh call can prompt, and one to a guest that stops
/// answering ends after 10 keepalives 30 s apart; host keys are still
/// checked strictly. Without it the lab's options are unchanged.
#[test]
fn nn_lab_ci_mode_never_prompts_and_bounds_a_dead_guest() {
    if !have("ssh") {
        eprintln!("SKIP: no ssh client");
        return;
    }
    let ci = ssh_config(Some("1"), "ssh-ci");
    for want in [
        "batchmode yes",
        "serveraliveinterval 30",
        "serveralivecountmax 10",
        "stricthostkeychecking true",
        "hostkeyalgorithms ssh-ed25519",
    ] {
        assert!(ci.lines().any(|l| l == want), "CI mode: no `{want}`");
    }
    let lab = ssh_config(None, "ssh-lab");
    assert!(
        lab.lines().any(|l| l == "batchmode no"),
        "the lab's ssh is unchanged"
    );
    assert!(lab.lines().any(|l| l == "serveraliveinterval 0"));
    assert!(lab.lines().any(|l| l == "stricthostkeychecking true"));
}

/// In CI mode every cargo build is --locked (external audit SUP-016): the
/// host's eBPF build and every build and test run in the guest, through
/// one variable that is empty in the lab. test-ignored frames its five
/// cargo runs for gate-summary, and a boot that fails shows the guest's
/// console in CI mode.
#[test]
fn nn_lab_ci_mode_builds_locked_and_frames_the_gate() {
    let text = read(NN_LAB);
    assert!(text.contains(
        "LAB_CARGO_LOCKED=\nif [[ $CI_MODE == 1 ]]; then LAB_CARGO_LOCKED=--locked; fi\n"
    ));
    let mut cargo_runs = 0;
    for (n, l) in text.lines().enumerate() {
        let code = l.trim_start();
        if code.starts_with('#') {
            continue;
        }
        for c in ["cargo test --release", "cargo build --release"] {
            if code.contains(c) {
                cargo_runs += 1;
                assert!(
                    code.contains(&format!("{c} $LAB_CARGO_LOCKED")),
                    "{NN_LAB}:{}: `{c}` without $LAB_CARGO_LOCKED",
                    n + 1
                );
            }
        }
    }
    assert!(cargo_runs >= 8, "{cargo_runs}");
    assert!(text.contains(
        "cargo ${LAB_CARGO_LOCKED:+--locked} xtask build-ebpf ${LAB_CARGO_LOCKED:+--locked}"
    ));
    let body = &text[text.find("cmd_test_ignored() {").unwrap()..];
    let body = &body[..body.find("\n}\n").unwrap()];
    for i in 1..=5 {
        assert!(
            body.contains(&format!("lab_ignored_run {i}/5 \"")),
            "run {i}/5"
        );
    }
    assert!(
        !body.contains("    vcargo "),
        "every cargo run of test-ignored is framed"
    );
    let runner = &text[text.find("lab_ignored_run() {").unwrap()..];
    assert!(runner.contains("log \"test-ignored run $1 start: $2\""));
    assert!(runner.contains("log \"test-ignored run $1 end: $2: exit $rc\""));
    let wait = &text[text.find("wait_ssh() {").unwrap()..];
    let wait = &wait[..wait.find("\n}\n").unwrap()];
    assert!(wait.contains("lab_serial_tail\n    die \"guest did not become reachable"));
}

/// The download self-test (deploy/lab/lib/verify-download-test.sh), which
/// covers image-info and fetch-image too: a restored image is checked
/// against the current list in CI mode and replaced when it is another one,
/// never in the lab. Needs GnuPG; skipped without it.
#[test]
fn the_download_self_test_passes() {
    if !(have("gpg") && have("gpgv") && have("gpgconf")) {
        eprintln!("SKIP: no GnuPG on this host");
        return;
    }
    let out = Command::new("bash")
        .arg(repo_root().join("deploy/lab/lib/verify-download-test.sh"))
        .env_remove("CI_MODE")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let t = text(&out);
    assert!(out.status.success(), "{t}");
    assert!(t.contains("== CI glue (image-info, fetch-image)"), "{t}");
    assert!(t.contains(" passed, 0 failed"), "{t}");
}

// ── the expected failures ─────────────────────────────────────────────────

fn expected_rows() -> Vec<Vec<String>> {
    read(EXPECTED)
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| l.split('\t').map(str::to_string).collect())
        .collect()
}

/// Each expected failure is a recorded follow-up of one guest nn-lab.sh
/// knows, on a test that exists in its suite. The one the gate started with,
/// Debian 13's DNS attribution (nss-resolve), is gone since lab PR 229 fixed
/// it: the list holds no line for it, and the real list run through
/// gate-summary passes a Debian 13 run where that test passes.
#[test]
fn expected_failures_are_recorded_follow_ups() {
    let nn_lab = read(NN_LAB);
    let rows = expected_rows();
    for r in &rows {
        assert_eq!(r.len(), 4, "{EXPECTED}: {r:?}");
        let (distro, suite, test, follow_up) = (&r[0], &r[1], &r[2], &r[3]);
        assert!(
            nn_lab.contains(&format!("\n    {distro})\n")),
            "{EXPECTED}: {distro} is not a guest of nn-lab.sh"
        );
        let file = ["agent/tests", "watchdog/tests"]
            .iter()
            .map(|d| repo_root().join(d).join(format!("{suite}.rs")))
            .find(|p| p.exists())
            .unwrap_or_else(|| panic!("{EXPECTED}: no suite {suite}"));
        let fn_name = test.rsplit("::").next().unwrap();
        assert!(
            fs::read_to_string(&file)
                .unwrap()
                .contains(&format!("fn {fn_name}(")),
            "{EXPECTED}: {suite} has no test {test}"
        );
        assert!(
            follow_up.contains("lab PR") || follow_up.contains("EXTERNAL_AUDIT"),
            "{EXPECTED}: {test}: the follow-up names where it is recorded"
        );
    }
    assert!(
        rows.iter().all(|r| r[2] != DNS_TEST),
        "{EXPECTED}: lab PR 229 fixed the DNS attribution under nss-resolve: {rows:?}"
    );
    let dir = case_dir("real-list");
    let log = dir.join("gate.log");
    fs::write(&log, gate_log(true, "", None)).unwrap();
    let out = Command::new(XTASK)
        .arg("gate-summary")
        .arg("--log")
        .arg(&log)
        .args(["--distro", "debian13", "--kernel", "6.x-test", "--rc", "0"])
        .arg("--expected")
        .arg(repo_root().join(EXPECTED))
        .arg("--json")
        .arg(dir.join("gate-summary.json"))
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    let j: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(dir.join("gate-summary.json")).unwrap()).unwrap();
    assert_eq!(j["verdict"], "pass");
    assert_eq!(j["expected_failures"].as_array().map(Vec::len), Some(0));
}

// ── gate-summary and gate-report ──────────────────────────────────────────

const DNS_TEST: &str = "net_outbound_connect_records_flow_with_dns_attribution";

/// A libtest run of one suite: (test, passed).
fn suite_log(suite: &str, tests: &[(&str, bool)]) -> String {
    let mut s = format!(
        "     Running tests/{suite}.rs (target/release/deps/{suite}-0123456789abcdef)\n\nrunning {} tests\n",
        tests.len()
    );
    for (t, ok) in tests {
        if *ok {
            s.push_str(&format!("test {t} ... ok\n"));
        } else {
            // a child of the test wrote to the inherited stderr meanwhile
            s.push_str(&format!(
                "test {t} ... 2026-10-21T01:00:00Z  INFO northnarrow_agent: started\nFAILED\n"
            ));
        }
    }
    let failed: Vec<&str> = tests
        .iter()
        .filter(|(_, ok)| !ok)
        .map(|(t, _)| *t)
        .collect();
    if !failed.is_empty() {
        s.push_str("\nfailures:\n\n");
        for t in &failed {
            s.push_str(&format!(
                "---- {t} stdout ----\n\nthread '{t}' panicked at agent/tests/{suite}.rs:1:1:\n    an indented line of output\n\n"
            ));
        }
        s.push_str("\nfailures:\n");
        for t in &failed {
            s.push_str(&format!("    {t}\n"));
        }
    }
    s.push_str(&format!(
        "\ntest result: {}. {} passed; {} failed; 0 ignored; 0 measured; 3 filtered out; finished in 1.00s\n\n",
        if failed.is_empty() { "ok" } else { "FAILED" },
        tests.len() - failed.len(),
        failed.len()
    ));
    if !failed.is_empty() {
        s.push_str(&format!(
            "error: test failed, to rerun pass `-p northnarrow-agent --test {suite}`\n\nCaused by:\n  process didn't exit successfully: `target/release/deps/{suite}-0123456789abcdef --ignored` (exit status: 101)\n"
        ));
    }
    s
}

fn run_frame(n: usize, body: &str, exit: Option<i32>) -> String {
    let mut s = format!("nn-lab: test-ignored run {n}/5 start: run {n}\n{body}");
    if let Some(e) = exit {
        s.push_str(&format!(
            "nn-lab: test-ignored run {n}/5 end: run {n}: exit {e}\n"
        ));
    }
    s
}

/// A whole test-ignored log: five runs, run 3 holding `net` (the DNS test
/// passing or not) and `extra`.
fn gate_log(dns_ok: bool, extra: &str, run3_exit: Option<i32>) -> String {
    let mut s =
        String::from("nn-lab: NN_LAB_IGNORED_SKIP: skipping the tests matching: soak::long\n");
    s.push_str(&run_frame(
        1,
        &suite_log("fixture_selftest", &[("iptables::iptables_guard_a", true)]),
        Some(0),
    ));
    s.push_str(&run_frame(
        2,
        &suite_log(
            "privileged_map_pin",
            &[(
                "protected_pids_kernel_id_is_stable_across_agent_restart",
                true,
            )],
        ),
        Some(0),
    ));
    let run3 = format!(
        "{}{}{extra}",
        suite_log(
            "net_privileged_e2e",
            &[(DNS_TEST, dns_ok), ("net_udp_flow_recorded", true)]
        ),
        suite_log("canary_privileged_e2e", &[("canary_trips", true)]),
    );
    let exit3 = run3_exit.or(Some(if dns_ok { 0 } else { 101 }));
    s.push_str(&run_frame(3, &run3, exit3));
    s.push_str(&run_frame(
        4,
        &suite_log("privileged_e2e", &[("watchdog_respawns", true)]),
        Some(0),
    ));
    s.push_str(&run_frame(
        5,
        &suite_log("fim_privileged_e2e", &[("fim_detects", true)]),
        Some(0),
    ));
    s
}

struct Gate {
    status: Option<i32>,
    out: String,
    json: serde_json::Value,
    markdown: String,
}

fn gate_summary(name: &str, log: Option<&str>, distro: &str, extra: &[&str]) -> Gate {
    let dir = case_dir(name);
    let log_path = dir.join("gate.log");
    if let Some(l) = log {
        fs::write(&log_path, l).unwrap();
    }
    let json = dir.join("gate-summary.json");
    let md = dir.join("gate-summary.md");
    let out = Command::new(XTASK)
        .arg("gate-summary")
        .arg("--log")
        .arg(&log_path)
        .args([
            "--distro",
            distro,
            "--kernel",
            "6.x-test",
            "--commit",
            "0123456789abcdef0123456789abcdef01234567",
        ])
        .arg("--expected")
        .arg(expected_fixture(&dir))
        .arg("--json")
        .arg(&json)
        .arg("--markdown")
        .arg(&md)
        .args(extra)
        .output()
        .unwrap();
    let j =
        fs::read_to_string(&json).unwrap_or_else(|_| panic!("no summary written: {}", text(&out)));
    Gate {
        status: out.status.code(),
        out: text(&out),
        json: serde_json::from_str(&j).unwrap(),
        markdown: fs::read_to_string(&md).unwrap_or_default(),
    }
}

/// An expected-failures list in `deploy/lab/expected-failures.tsv`'s
/// format holding the one line the gate started with (Debian 13's DNS
/// attribution under nss-resolve), for the gate-summary and gate-report
/// tests: they check the mechanism, whatever the real list holds today
/// (lab PR 229 closed that follow-up and removed its line).
fn expected_fixture(dir: &Path) -> PathBuf {
    let path = dir.join("expected-failures.tsv");
    let header: String = read(EXPECTED)
        .lines()
        .take_while(|l| l.starts_with('#'))
        .map(|l| format!("{l}\n"))
        .collect();
    fs::write(
        &path,
        format!(
            "{header}debian13\tnet_privileged_e2e\t{DNS_TEST}\tDNS attribution on hosts that \
             resolve through systemd-resolved (nss-resolve; a fixture of the line lab PR 164 \
             recorded)\n"
        ),
    )
    .unwrap();
    path
}

fn reasons(g: &Gate) -> String {
    g.json["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r.as_str().unwrap().to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Debian 13's DNS attribution fails as the follow-up says: the run passes,
/// and the summary shows it — counted in `failed`, listed with its outcome
/// and follow-up, apart from the passes. The same log on another guest
/// fails: an expected failure belongs to its distro only.
#[test]
fn gate_summary_shows_an_expected_failure_and_only_on_its_guest() {
    let log = gate_log(false, "", None);
    let g = gate_summary(
        "xfail-d13",
        Some(&log),
        "debian13",
        &["--rc", "1", "--step", "up=success"],
    );
    assert_eq!(g.status, Some(0), "{}", g.out);
    assert_eq!(g.json["verdict"], "pass");
    let t = &g.json["totals"];
    assert_eq!(
        (
            t["suites"].as_u64(),
            t["passed"].as_u64(),
            t["failed"].as_u64()
        ),
        (Some(6), Some(6), Some(1))
    );
    assert_eq!(t["expected_failures"].as_u64(), Some(1));
    assert_eq!(g.json["expected_failures"][0]["test"], DNS_TEST);
    assert_eq!(
        g.json["expected_failures"][0]["outcome"],
        "failed as expected"
    );
    assert!(
        g.json["expected_failures"][0]["follow_up"]
            .as_str()
            .unwrap()
            .contains("nss")
            || g.json["expected_failures"][0]["follow_up"]
                .as_str()
                .unwrap()
                .contains("systemd-resolved")
    );
    assert_eq!(g.json["failed_tests"][0]["expected"], true);
    assert_eq!(g.json["kernel"], "6.x-test");
    assert_eq!(g.json["runs"].as_array().unwrap().len(), 5);
    assert!(
        g.markdown
            .contains("| debian13 | 6.x-test | 6 | 6 | 1 | 1 | 0 | ✅ pass (1 expected failure) |"),
        "{}",
        g.markdown
    );
    assert!(g.markdown.contains(&format!(
        "`net_privileged_e2e` › `{DNS_TEST}`: **failed as expected**"
    )));
    assert!(
        g.markdown
            .contains("skipping the tests matching: soak::long"),
        "the note is kept"
    );

    let g = gate_summary("xfail-u2404", Some(&log), "ubuntu2404", &["--rc", "1"]);
    assert_eq!(g.status, Some(1), "{}", g.out);
    assert_eq!(g.json["verdict"], "fail");
    assert!(
        reasons(&g).contains(&format!("failed: `net_privileged_e2e` › `{DNS_TEST}`")),
        "{}",
        reasons(&g)
    );
    assert_eq!(g.json["expected_failures"].as_array().unwrap().len(), 0);
}

/// The list cannot go stale: an expected failure that passes, or that does
/// not run, fails the run and says what to do.
#[test]
fn gate_summary_fails_a_stale_expected_failure() {
    let g = gate_summary(
        "xpass",
        Some(&gate_log(true, "", None)),
        "debian13",
        &["--rc", "0"],
    );
    assert_eq!(g.status, Some(1), "{}", g.out);
    assert_eq!(g.json["expected_failures"][0]["outcome"], "passed");
    assert!(
        reasons(&g).contains("remove its line from deploy/lab/expected-failures.tsv"),
        "{}",
        reasons(&g)
    );

    let renamed = gate_log(true, "", None).replace(DNS_TEST, "net_dns_attribution_renamed");
    let g = gate_summary("xrenamed", Some(&renamed), "debian13", &["--rc", "0"]);
    assert_eq!(g.status, Some(1));
    assert_eq!(g.json["expected_failures"][0]["outcome"], "did not run");

    let ignored = gate_log(true, "", None).replace(
        &format!("test {DNS_TEST} ... ok"),
        &format!("test {DNS_TEST} ... ignored"),
    );
    let g = gate_summary("xignored", Some(&ignored), "debian13", &["--rc", "0"]);
    assert_eq!(g.status, Some(1));
    assert_eq!(g.json["expected_failures"][0]["outcome"], "did not run");
}

/// What a count of `test result:` lines cannot see: a test binary that died
/// without its summary (killed, a timeout, the guest gone), a cargo run that
/// failed without a failing test (a build error), a run that never ended,
/// a run that never started — each fails the gate, expected failure or not.
#[test]
fn gate_summary_fails_what_no_summary_line_shows() {
    let crashed = "error: test failed, to rerun pass `-p northnarrow-agent --test response_privileged_e2e`\n\nCaused by:\n  process didn't exit successfully: `x` (signal: 9, SIGKILL: kill)\n";
    let g = gate_summary(
        "crash",
        Some(&gate_log(false, crashed, None)),
        "debian13",
        &["--rc", "1"],
    );
    assert_eq!(g.status, Some(1), "{}", g.out);
    assert!(
        reasons(&g).contains("1 test binary failed without a libtest summary"),
        "{}",
        reasons(&g)
    );

    let build = "error[E0425]: cannot find value `x` in this scope\nerror: could not compile `northnarrow-agent` (lib) due to 1 previous error\n";
    let log = gate_log(true, "", None).replace(
        "nn-lab: test-ignored run 4/5 start: run 4\n",
        &format!("nn-lab: test-ignored run 4/5 start: run 4\n{build}nn-lab: test-ignored run 4/5 end: run 4: exit 101\nnn-lab: test-ignored run 4/5 start: run 4b\n"),
    );
    let g = gate_summary("build-error", Some(&log), "ubuntu2404", &["--rc", "1"]);
    assert_eq!(g.status, Some(1));
    let r = reasons(&g);
    assert!(r.contains("the build failed"), "{r}");
    assert!(
        r.contains("cargo run 4/5 (run 4) exited 101 without a failed test summary"),
        "{r}"
    );

    let cut = gate_log(true, "", None);
    let cut = &cut[..cut.find("nn-lab: test-ignored run 4/5 start").unwrap()];
    let cut = cut.replace("nn-lab: test-ignored run 3/5 end: run 3: exit 0\n", "");
    let g = gate_summary("cut", Some(&cut), "ubuntu2404", &[]);
    assert_eq!(g.status, Some(1));
    let r = reasons(&g);
    assert!(r.contains("cargo run 3/5 (run 3) did not finish"), "{r}");
    assert!(
        r.contains("3 of test-ignored's 5 cargo runs started"),
        "{r}"
    );

    let died = format!(
        "{}nn-lab: ERROR: guest is not running\n",
        gate_log(true, "", None)
    );
    let g = gate_summary("lab-error", Some(&died), "ubuntu2404", &["--rc", "1"]);
    assert_eq!(g.status, Some(1));
    assert!(reasons(&g).contains("nn-lab.sh: guest is not running"));
}

/// A job that stopped before the gate (the boot, the build) still writes a
/// summary: which step failed, and that no suite ran.
#[test]
fn gate_summary_reports_a_gate_that_did_not_run() {
    let g = gate_summary(
        "no-log",
        None,
        "debian12",
        &[
            "--step",
            "kvm=success",
            "--step",
            "up=failure",
            "--step",
            "test-ignored=skipped",
        ],
    );
    assert_eq!(g.status, Some(1));
    let r = reasons(&g);
    assert!(r.contains("step `up`: failure"), "{r}");
    assert!(r.contains("step `test-ignored`: skipped"), "{r}");
    assert!(r.contains("no gate log"), "{r}");
    assert!(
        g.markdown.contains("up ❌") && g.markdown.contains("kvm ✅"),
        "{}",
        g.markdown
    );
    assert!(g.markdown.contains("— FAIL"));

    let g = gate_summary(
        "all-green",
        Some(&gate_log(true, "", None)),
        "ubuntu2204",
        &["--rc", "0", "--step", "up=success"],
    );
    assert_eq!(g.status, Some(0), "{}", g.out);
    assert_eq!(g.json["totals"]["failed"].as_u64(), Some(0));
}

/// The maintainer's report: one row per guest in the lab's order, the
/// expected failures and every failure's reason, from the artefacts as
/// `gh run download` lays them out.
#[test]
fn gate_report_tabulates_the_artefacts_of_a_run() {
    let d13 = gate_summary(
        "report-d13",
        Some(&gate_log(false, "", None)),
        "debian13",
        &["--rc", "1", "--run-url", "https://example.invalid/runs/1"],
    );
    let u22 = gate_summary(
        "report-u22",
        Some(&gate_log(true, "", None)),
        "ubuntu2204",
        &["--rc", "0"],
    );
    assert_eq!((d13.status, u22.status), (Some(0), Some(0)));
    let dl = case_dir("report");
    for (name, src) in [
        ("lab-gate-debian13", "report-d13"),
        ("lab-gate-ubuntu2204", "report-u22"),
    ] {
        fs::create_dir_all(dl.join(name)).unwrap();
        fs::copy(
            case_dir_path(src).join("gate-summary.json"),
            dl.join(name).join("gate-summary.json"),
        )
        .unwrap();
    }
    let out = Command::new(XTASK)
        .arg("gate-report")
        .arg(&dl)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out));
    let md = String::from_utf8_lossy(&out.stdout);
    let u = md.find("| ubuntu2204 |").expect(&md);
    let d = md.find("| debian13 |").expect(&md);
    assert!(u < d, "the lab's order:\n{md}");
    assert!(md.contains("`0123456789ab`"), "{md}");
    assert!(md.contains("https://example.invalid/runs/1"));
    assert!(
        md.contains(&format!(
            "debian13: `net_privileged_e2e` › `{DNS_TEST}`: **failed as expected**"
        )),
        "{md}"
    );
    assert!(md.contains("Every guest passed."));
    let none = Command::new(XTASK)
        .arg("gate-report")
        .arg(case_dir("report-empty"))
        .output()
        .unwrap();
    assert!(
        !none.status.success(),
        "a directory without summaries is an error"
    );
}

fn case_dir_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("lab-ci")
        .join(name)
}
