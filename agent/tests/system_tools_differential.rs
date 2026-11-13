//! Lot 316 (external bug hunt, edition 1.4: BUG-106, BUG-89, N4): the
//! system tools' option tables (`nn_core::impair`'s `tool_options`, read by
//! `posture::script_args`' one reader), checked against the real tools.
//!
//! For each tool present on the host a fixed corpus of argvs — the
//! spellings of the hunt and of its mini-hunt — and a few hundred generated
//! from a vocabulary of the tool's options, with a deterministic generator
//! (no dependency). Each argv runs the real tool on a target of its own,
//! where it can reach nothing else; what it did is then compared with what
//! the detector ([`DefenseDetector`]) makes of the same exec:
//!
//! - `pkill`, `killall`: a copy of `sleep` named `nn316diffsleep`, in a PID
//!   namespace of its own (`unshare -p --mount-proc`, `-r` when not root):
//!   ended or stopped, or not;
//! - `iptables`, `nft` (root): in a network namespace of its own (`unshare
//!   -n`), a rule of INPUT and a DROP policy, two nft tables: flushed (the
//!   rule gone, or both tables) or the policy ACCEPT, or not;
//! - `systemctl` (root, under systemd): a transient unit `nn316diff`
//!   (`systemd-run`, a `sleep`): stopped, killed or frozen, or not.
//!
//! A mismatch is an evasion: the tool switched its target off and the
//! detector saw nothing. A finding with no effect (the tool refused the
//! argv, or the reading over-approximates) is counted, not judged.
//!
//! `#[ignore]` and a no-op without `NN_DIFF_SYSTEM_TOOLS=1`: it runs
//! hundreds of processes and, as root, changes namespaces and a transient
//! unit of its own (none of the host's). Run it on a lab guest (`sudo -E env
//! NN_DIFF_SYSTEM_TOOLS=1 cargo test -p northnarrow-agent --test
//! system_tools_differential -- --ignored --nocapture`) or, for the kill
//! family alone, on a developer's host. (In the agent's tests: nn-core is a
//! pure crate, its tests reach no OS interface.)

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

use nn_model::{Event, ExeIdentity};
use northnarrow_agent::impair::{
    DefenseDetector, EvaRule, SecurityTools, BUILTIN_SECURITY_TOOLS_V1,
};
use northnarrow_agent::posture::lineage::AuthSessionTracker;

const S: u64 = 1_000_000_000;

/// A small xorshift: the corpus is the same on every run.
struct Gen(u64);

impl Gen {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn pick<'a>(&mut self, v: &[&'a str]) -> &'a str {
        v[(self.next() % v.len() as u64) as usize]
    }
}

fn enabled() -> bool {
    std::env::var("NN_DIFF_SYSTEM_TOOLS").as_deref() == Ok("1")
}

fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
}

fn which(tool: &str) -> Option<PathBuf> {
    ["/usr/sbin", "/usr/bin", "/sbin", "/bin"]
        .iter()
        .map(|d| Path::new(d).join(tool))
        .find(|p| p.exists())
}

/// The detector on the shipped list and a test tool (`unit=nn316diff`, its
/// process the copy of sleep), its lineage a non-interactive root shell.
struct Judge {
    _proc: tempfile::TempDir,
    lineage: AuthSessionTracker,
    det: DefenseDetector,
    pid: std::cell::Cell<u32>,
}

impl Judge {
    fn new(sleep_copy: &Path) -> Self {
        let proc = tempfile::TempDir::new().unwrap();
        let lineage = AuthSessionTracker::new(proc.path());
        lineage.ingest_exec(150, 1, "/usr/sbin/cron", &["cron".into()], S, S, 0);
        lineage.ingest_exec(200, 150, "/usr/bin/bash", &["bash".into()], 2 * S, 2 * S, 0);
        let list = format!(
            "{BUILTIN_SECURITY_TOOLS_V1}\ntool nn316diff class=edr unit=nn316diff proc={}\n",
            sleep_copy.display()
        );
        let tools = SecurityTools::parse(&list).expect("the list parses");
        let det =
            DefenseDetector::with_proc_root(Arc::new(tools), lineage.clone(), None, proc.path());
        Self {
            _proc: proc,
            lineage,
            det,
            pid: std::cell::Cell::new(10_000),
        }
    }

    /// What the detector makes of `exe` run with `argv`: the rule and tool.
    fn judge(&self, exe: &Path, argv: &[String]) -> Option<(EvaRule, String)> {
        let pid = self.pid.get() + 1;
        self.pid.set(pid);
        let at = 100 * S + u64::from(pid);
        let exe = exe.to_string_lossy().into_owned();
        self.lineage.ingest_exec(pid, 200, &exe, argv, at, at, 0);
        let e = Event::ProcessSpawn {
            pid,
            ppid: 200,
            uid: 0,
            gid: 0,
            comm: exe.rsplit('/').next().unwrap().chars().take(15).collect(),
            filename: exe.clone(),
            timestamp_ns: at,
            argv: argv.to_vec(),
            parent_comm: String::new(),
            parent_start_ns: 0,
            start_ns: 0,
            parent_is_kthread: false,
            exe: ExeIdentity::default(),
            argv_truncated: false,
            filename_truncated: false,
            stdio: Default::default(),
        };
        self.det.assess(&e).map(|f| (f.rule, f.tool))
    }
}

/// One family's tally.
#[derive(Default)]
struct Tally {
    runs: usize,
    effects: usize,
    findings_without_effect: usize,
    unclear: usize,
    /// Kills by a pattern less than half of the target's name (`pkill
    /// sleep` ends `nn316diffsleep`): no exec-side record by design — the
    /// pattern names no tool (`pkill -f agent` is anyone's) — and the signal
    /// itself is NN-L-EVA-003 on `task_kill` (a registered tool's process).
    left_to_task_kill: usize,
    mismatches: Vec<String>,
}

impl Tally {
    fn add(&mut self, argv: &[String], effect: Option<bool>, found: bool) {
        self.runs += 1;
        match effect {
            None => self.unclear += 1,
            Some(true) => {
                self.effects += 1;
                if !found {
                    self.mismatches.push(format!("{argv:?}"));
                }
            }
            Some(false) if found => self.findings_without_effect += 1,
            Some(false) => {}
        }
    }

    fn report(&self, name: &str) {
        eprintln!(
            "{name}: {} argvs, {} switched the target off, {} findings without an effect, {} \
             unclear, {} left to task_kill, {} mismatches",
            self.runs,
            self.effects,
            self.findings_without_effect,
            self.unclear,
            self.left_to_task_kill,
            self.mismatches.len()
        );
    }
}

/// `sh -c script sh args…`, its first line of output.
fn sh(prefix: &[&str], script: &str, args: &[String]) -> Option<String> {
    let mut c = Command::new(prefix[0]);
    c.args(&prefix[1..])
        .args(["timeout", "20", "sh", "-c", script, "sh"])
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null());
    let out = c.output().ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .last()
        .map(str::to_string)
}

/// The kill family, in a PID namespace of its own.
fn kill_family(judge: &Judge, sleep_copy: &Path, tally: &mut Tally) {
    let ns: &[&str] = if is_root() {
        &["unshare", "-p", "-f", "--mount-proc"]
    } else {
        &["unshare", "-r", "-p", "-f", "--mount-proc"]
    };
    let probe = "\"$1\" 600 & p=$!; shift; i=0; \
                 while [ \"$(cut -d' ' -f3 /proc/$p/stat 2>/dev/null)\" != S ] && [ $i -lt 50 ]; do \
                 i=$((i+1)); sleep 0.01; done; \
                 timeout 5 \"$@\" >/dev/null 2>&1; sleep 0.1; \
                 st=$(cut -d' ' -f3 /proc/$p/stat 2>/dev/null); \
                 case \"$st\" in S|R|D) echo ALIVE;; *) echo ENDED;; esac";
    let name = "nn316diffsleep";
    let path = sleep_copy.to_string_lossy().into_owned();
    let names = [
        name,
        "nn316diff",
        "316diffsl",
        "NN316DIFFSLEEP",
        "^nn316diffsleep$",
        "nn316diffsleepx",
        path.as_str(),
        "sleep",
    ];
    let fixed: Vec<(&str, Vec<&str>)> = vec![
        ("pkill", vec!["-n", name]),
        ("pkill", vec!["-o", name]),
        ("pkill", vec!["-c", name]),
        ("pkill", vec!["-9", "-n", name]),
        ("pkill", vec!["-KILL", name]),
        ("pkill", vec!["--signal=KILL", name]),
        ("pkill", vec!["--sig", "TERM", name]),
        ("pkill", vec!["-x", "nn316diff"]),
        ("pkill", vec!["nn316diff"]),
        ("pkill", vec!["-i", "NN316DIFFSLEEP"]),
        ("pkill", vec!["-f", &path]),
        ("pkill", vec![name, "-n"]),
        ("killall", vec!["-g", name]),
        ("killall", vec!["-e", name]),
        ("killall", vec!["-signal", "KILL", name]),
        ("killall", vec!["-sig", "KILL", name]),
        ("killall", vec!["-KILL", name]),
        ("killall", vec!["-I", "NN316DIFFSLEEP"]),
        ("killall", vec![&path]),
        ("killall", vec!["-r", "316diff"]),
        ("killall", vec!["-o", "1s", name]),
    ];
    let pkill_vocab = [
        "-n",
        "-o",
        "-c",
        "-x",
        "-f",
        "-i",
        "-e",
        "-9",
        "-KILL",
        "-TERM",
        "-STOP",
        "-CONT",
        "-0",
        "--signal",
        "KILL",
        "--signal=TERM",
        "--sig",
        "-s",
        "0",
        "-g",
        "0",
        "-u",
        "0",
        "--exact",
        "--full",
        "--newest",
        "--oldest",
        "--ignore-case",
        "-A",
        "-H",
        "--echo",
        "--",
    ];
    let killall_vocab = [
        "-g",
        "-e",
        "-I",
        "-q",
        "-r",
        "-w",
        "-v",
        "-i",
        "-s",
        "KILL",
        "-signal",
        "-sig",
        "TERM",
        "-KILL",
        "-STOP",
        "-9",
        "-o",
        "1s",
        "-y",
        "1h",
        "--exact",
        "--process-group",
        "-ve",
        "--signal=TERM",
        "--",
    ];
    let mut g = Gen(0x316_0001);
    let mut cases: Vec<(String, Vec<String>)> = fixed
        .into_iter()
        .map(|(t, a)| (t.to_string(), a.into_iter().map(String::from).collect()))
        .collect();
    for _ in 0..300 {
        let (tool, vocab): (&str, &[&str]) = if g.next() % 2 == 0 {
            ("pkill", &pkill_vocab)
        } else {
            ("killall", &killall_vocab)
        };
        let n = 1 + (g.next() % 4) as usize;
        let mut a: Vec<String> = (0..n).map(|_| g.pick(vocab).to_string()).collect();
        let at = (g.next() % (a.len() as u64 + 1)) as usize;
        a.insert(at, g.pick(&names).to_string());
        cases.push((tool.to_string(), a));
    }
    for (tool, args) in cases {
        let Some(exe) = which(&tool) else { continue };
        let mut argv = vec![tool.clone()];
        argv.extend(args.iter().cloned());
        let mut run = vec![path.clone(), exe.to_string_lossy().into_owned()];
        run.extend(args.iter().cloned());
        let effect = match sh(ns, probe, &run).as_deref() {
            Some("ENDED") => Some(true),
            Some("ALIVE") => Some(false),
            _ => None,
        };
        let found = judge
            .judge(&exe, &argv)
            .is_some_and(|(r, t)| r == EvaRule::Killed && t == "nn316diff");
        if effect == Some(true) && !found && args.iter().any(|a| a == "sleep") {
            tally.runs += 1;
            tally.effects += 1;
            tally.left_to_task_kill += 1;
            continue;
        }
        tally.add(&argv, effect, found);
    }
}

/// iptables and nft, root, in a network namespace of their own.
fn firewall(judge: &Judge, ipt: &mut Tally, nft: &mut Tally) {
    let ipt_probe = "iptables -P INPUT DROP && iptables -A INPUT -s 192.0.2.7 -j DROP || exit 3; \
                     timeout 5 \"$@\" >/dev/null 2>&1; s=$(iptables -S INPUT); \
                     case \"$s\" in *'-P INPUT ACCEPT'*) echo OFF; exit;; esac; \
                     case \"$s\" in *192.0.2.7*) echo KEPT;; *) echo OFF;; esac";
    // the ruleset flushed: both tables gone (a `delete table` of one is not
    // the listed `flush ruleset`)
    let nft_probe = "nft add table inet nn316 && nft add chain inet nn316 c && \
                     nft add table ip nn316b || exit 3; \
                     timeout 5 \"$@\" >/dev/null 2>&1; \
                     nft list tables | grep -q nn316 && echo KEPT || echo OFF";
    if let Some(exe) = which("iptables") {
        let multi = which("xtables-nft-multi");
        let fixed: &[&[&str]] = &[
            &["-F"],
            &["--flush"],
            &["--fl"],
            &["-FINPUT"],
            &["--flush=INPUT"],
            &["-w", "-F"],
            &["-w", "1", "-F"],
            &["-vF"],
            &["-P", "INPUT", "ACCEPT"],
            &["--policy", "INPUT", "ACCEPT"],
            &["--pol", "INPUT", "ACCEPT"],
            &["-PINPUT", "ACCEPT"],
            &["--policy=INPUT", "ACCEPT"],
            &["-t", "filter", "-F", "INPUT"],
            &["-A", "INPUT", "-j", "LOG", "--log-prefix", "-F"],
            &["-L", "-n"],
            &["-S"],
            &["-P", "INPUT", "DROP"],
        ];
        let vocab = [
            "-F",
            "--flush",
            "--fl",
            "-FINPUT",
            "INPUT",
            "FORWARD",
            "-P",
            "--policy",
            "--pol",
            "ACCEPT",
            "DROP",
            "-w",
            "1",
            "-t",
            "filter",
            "nat",
            "-v",
            "-n",
            "-L",
            "-S",
            "-Z",
            "-X",
            "!",
            "-x",
            "--wait",
            "-W",
            "--line-numbers",
        ];
        let mut g = Gen(0x316_0002);
        let mut cases: Vec<Vec<String>> = fixed
            .iter()
            .map(|a| a.iter().map(|s| s.to_string()).collect())
            .collect();
        for _ in 0..200 {
            let n = 1 + (g.next() % 5) as usize;
            cases.push((0..n).map(|_| g.pick(&vocab).to_string()).collect());
        }
        for (k, args) in cases.into_iter().enumerate() {
            // by its names: iptables, and the multi-call binary's main4
            let (exe_run, argv): (PathBuf, Vec<String>) = match (&multi, k % 3) {
                (Some(m), 1) => (
                    m.clone(),
                    [
                        vec!["xtables-nft-multi".into(), "main4".into()],
                        args.clone(),
                    ]
                    .concat(),
                ),
                _ => (
                    exe.clone(),
                    [vec!["iptables".to_string()], args.clone()].concat(),
                ),
            };
            let mut run = vec![exe_run.to_string_lossy().into_owned()];
            // the multi-call binary run by its path reads argv[1]
            run.extend(argv.iter().skip(1).cloned());
            if exe_run != exe {
                run = [
                    vec![exe_run.to_string_lossy().into_owned()],
                    argv[1..].to_vec(),
                ]
                .concat();
            }
            let effect = match sh(&["unshare", "-n"], ipt_probe, &run).as_deref() {
                Some("OFF") => Some(true),
                Some("KEPT") => Some(false),
                _ => None,
            };
            let found = judge
                .judge(&exe_run, &argv)
                .is_some_and(|(r, t)| r == EvaRule::SwitchedOff && t == "iptables");
            ipt.add(&argv, effect, found);
        }
    }
    if let Some(exe) = which("nft") {
        let fixed: &[&[&str]] = &[
            &["flush", "ruleset"],
            &["flush ruleset"],
            &["--", "flush", "ruleset"],
            &["-c", "flush", "ruleset"],
            &["add table inet x; flush ruleset"],
            &["list tables\nflush\truleset"],
            &["flush", "ruleset", "inet"],
            &["list", "ruleset"],
            &["flush", "table", "inet", "nn316"],
            &["delete", "table", "inet", "nn316"],
        ];
        let vocab = [
            "flush",
            "ruleset",
            "flush ruleset",
            "list",
            "tables",
            "-c",
            "-a",
            "-e",
            "-n",
            "-s",
            "--",
            ";",
            "inet",
            "ip",
            "add table inet y;",
            "-t",
            "--check",
            "--handle",
        ];
        let mut g = Gen(0x316_0003);
        let mut cases: Vec<Vec<String>> = fixed
            .iter()
            .map(|a| a.iter().map(|s| s.to_string()).collect())
            .collect();
        for _ in 0..200 {
            let n = 1 + (g.next() % 4) as usize;
            cases.push((0..n).map(|_| g.pick(&vocab).to_string()).collect());
        }
        for args in cases {
            let argv = [vec!["nft".to_string()], args.clone()].concat();
            let run = [vec![exe.to_string_lossy().into_owned()], args].concat();
            let effect = match sh(&["unshare", "-n"], nft_probe, &run).as_deref() {
                Some("OFF") => Some(true),
                Some("KEPT") => Some(false),
                _ => None,
            };
            let found = judge
                .judge(&exe, &argv)
                .is_some_and(|(r, t)| r == EvaRule::SwitchedOff && t == "nftables");
            nft.add(&argv, effect, found);
        }
    }
}

/// systemctl, root under systemd: a transient unit of its own.
fn systemctl(judge: &Judge, tally: &mut Tally) {
    let Some(exe) = which("systemctl") else {
        return;
    };
    if !Path::new("/run/systemd/system").exists() {
        return;
    }
    let unit = "nn316diff";
    let reset = || {
        for a in [
            vec!["thaw", unit],
            vec!["stop", unit],
            vec!["reset-failed", unit],
        ] {
            let _ = Command::new(&exe).args(&a).stderr(Stdio::null()).status();
        }
    };
    let fixed: &[&[&str]] = &[
        &["stop", "nn316diff"],
        &["-P", "Id", "stop", "nn316diff"],
        &["--preset-mode", "full", "stop", "nn316diff"],
        &["--check-inhibitors", "no", "stop", "nn316diff"],
        &["--kill-whom", "main", "kill", "nn316diff"],
        &["--message", "x", "stop", "nn316diff"],
        &["--si", "KILL", "kill", "nn316diff"],
        &["-qs", "KILL", "kill", "nn316diff"],
        &["stop", "nn316diff", "--user"],
        &["--user", "--system", "stop", "nn316diff"],
        &["stop", "*316diff*"],
        &["stop", "nn316dif?.service"],
        &["freeze", "[n]n316diff.service"],
        &["stop", "-p", "nn316diff"],
        &["status", "nn316diff"],
        &["restart", "nn316diff"],
    ];
    let vocab = [
        "stop",
        "kill",
        "freeze",
        "status",
        "restart",
        "show",
        "nn316diff",
        "nn316diff.service",
        "nn316dif*",
        "*316diff*",
        "-q",
        "--no-block",
        "-s",
        "KILL",
        "--signal=TERM",
        "--si",
        "-P",
        "Id",
        "-p",
        "--kill-whom=main",
        "--kill-whom",
        "all",
        "--message",
        "x",
        "-i",
        "--now",
        "--job-mode",
        "replace",
        "--user",
        "--system",
        "-qs",
        "--",
        "--no-pager",
    ];
    let mut g = Gen(0x316_0004);
    let mut cases: Vec<Vec<String>> = fixed
        .iter()
        .map(|a| a.iter().map(|s| s.to_string()).collect())
        .collect();
    for _ in 0..150 {
        let n = 2 + (g.next() % 4) as usize;
        cases.push((0..n).map(|_| g.pick(&vocab).to_string()).collect());
    }
    for args in cases {
        reset();
        let started = Command::new("systemd-run")
            .args(["--quiet", "--unit", unit, "sleep", "600"])
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        if !started {
            tally.add(&args, None, false);
            continue;
        }
        let _ = Command::new("timeout")
            .arg("10")
            .arg(&exe)
            .args(&args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        std::thread::sleep(std::time::Duration::from_millis(200));
        let show = Command::new(&exe)
            .args(["show", "-p", "ActiveState", "-p", "FreezerState", unit])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default();
        let effect = if show.contains("ActiveState=active") {
            Some(show.contains("FreezerState=frozen"))
        } else if show.contains("ActiveState=") {
            Some(true)
        } else {
            None
        };
        let argv = [vec!["systemctl".to_string()], args].concat();
        let found = judge
            .judge(&exe, &argv)
            .is_some_and(|(r, t)| r == EvaRule::ServiceStopped && t == "nn316diff");
        tally.add(&argv, effect, found);
    }
    reset();
}

/// What the real tools did, never missed by the detector.
#[test]
#[ignore = "runs the real system tools (NN_DIFF_SYSTEM_TOOLS=1; root for iptables, nft, systemctl)"]
fn the_detector_reads_the_system_tools_as_they_read_themselves() {
    if !enabled() {
        eprintln!("NN_DIFF_SYSTEM_TOOLS not set: skipped");
        return;
    }
    let dir = tempfile::TempDir::new().unwrap();
    let sleep_copy = dir.path().join("nn316diffsleep");
    std::fs::copy(which("sleep").expect("sleep"), &sleep_copy).unwrap();
    let judge = Judge::new(&sleep_copy);
    let mut kills = Tally::default();
    kill_family(&judge, &sleep_copy, &mut kills);
    kills.report("pkill/killall");
    let (mut ipt, mut nft, mut sctl) = (Tally::default(), Tally::default(), Tally::default());
    if is_root() {
        firewall(&judge, &mut ipt, &mut nft);
        ipt.report("iptables");
        nft.report("nft");
        systemctl(&judge, &mut sctl);
        sctl.report("systemctl");
    } else {
        eprintln!("not root: iptables, nft and systemctl skipped");
    }
    let missed: Vec<&String> = [&kills, &ipt, &nft, &sctl]
        .iter()
        .flat_map(|t| t.mismatches.iter())
        .collect();
    assert!(kills.runs > 0, "no kill-family run");
    assert!(
        missed.is_empty(),
        "the tool switched its target off, the detector saw nothing: {missed:#?}"
    );
}
