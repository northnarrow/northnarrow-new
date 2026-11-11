//! Lot 310 (external bug hunt, edition 1.4; the triage's move 3, first
//! stage): the interpreters' option tables of `posture::script_args`,
//! checked against the real interpreters.
//!
//! For each interpreter present on the host (bash, dash, python3, perl;
//! busybox, zsh and mksh when installed) a fixed corpus of argvs — the
//! spellings of the three hunts (BUG-42, BUG-44, BUG-97, BUG-99, BUG-100) —
//! and a few thousand generated from a vocabulary of its options and of
//! three marker scripts, with a deterministic generator (no dependency). Each
//! argv runs the real interpreter in a temporary directory, its standard
//! input closed, its home the directory; each marker script and the inline
//! program append their name to a file when they run. What ran is then
//! compared with the reading ([`Runs`]):
//!
//! - `Script(p)`: nothing ran but `p` (an interpreter may refuse the argv
//!   and run nothing);
//! - `Code`: nothing ran but the inline program;
//! - `Inline` (nothing named): nothing ran;
//! - `Unknown`: anything (no trust is given) — counted, not judged.
//!
//! A mismatch is an identity a caller could move: the reading names a
//! script the interpreter did not run, or misses one it ran.
//!
//! `#[ignore]` and a no-op without `NN_DIFF_INTERPRETERS=1`: it runs
//! thousands of processes. Run it on a lab guest (`cargo test -p
//! northnarrow-agent --test interpreter_differential -- --ignored` with the
//! variable set) or on a developer's host; it writes only in its temporary
//! directory. (In the agent's tests: nn-core is a pure crate, its tests
//! reach no OS interface.)

use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use northnarrow_agent::posture::lineage::{ExecIdentity, Runs};

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

/// One interpreter: where it is, the `argv[0]` it is run with, its marker
/// script's text (`NAME` replaced), its inline program, and the vocabulary
/// of its argvs (`S1`…`S3`: the marker scripts; `CODE`: the inline
/// program).
struct Interp {
    exe: &'static str,
    argv0: &'static str,
    marker: &'static str,
    code: &'static str,
    vocab: &'static [&'static str],
    fixed: &'static [&'static [&'static str]],
}

const SHELL_MARKER: &str = "printf 'NAME\\n' >> \"$NN_DIFF_OUT\"\n";
const SHELL_CODE: &str = "printf 'C\\n' >> \"$NN_DIFF_OUT\"";
const SHELL_VOCAB: &[&str] = &[
    "S1",
    "S2",
    "S3",
    "S1",
    "S2",
    "CODE",
    "x",
    "-e",
    "-x",
    "-u",
    "-v",
    "-n",
    "-a",
    "-f",
    "-h",
    "-m",
    "-b",
    "-C",
    "-E",
    "-H",
    "-P",
    "-T",
    "-B",
    "-r",
    "-l",
    "-p",
    "-k",
    "-t",
    "-o",
    "+o",
    "pipefail",
    "errexit",
    "vi",
    "-O",
    "+O",
    "extglob",
    "-c",
    "+c",
    "-s",
    "-i",
    "-euo",
    "-ec",
    "-ce",
    "-eo",
    "-ovi",
    "-xe",
    "+e",
    "-norc",
    "-noprofile",
    "--norc",
    "--noprofile",
    "-rcfile",
    "--rcfile",
    "-init-file",
    "--init-file",
    "-posix",
    "--posix",
    "-login",
    "--login",
    "-restricted",
    "-verbose",
    "--verbose",
    "-debug",
    "--debug",
    "-noediting",
    "-D",
    "--",
    "-",
    "-V",
    "-I",
];
const SHELL_FIXED: &[&[&str]] = &[
    &["-noprofile", "S1", "x", "S2"],
    &["-norc", "S1"],
    &["-posix", "S1"],
    &["-restricted", "S1"],
    &["-verbose", "S1"],
    &["-rcfile", "S2", "S1"],
    &["-e", "-norc", "S1"],
    &["-e", "--norc", "S1"],
    &["-e", "S1"],
    &["-euo", "pipefail", "S1"],
    &["-c", "CODE", "S1"],
    &["-ec", "CODE", "S1"],
    &["-c", "-e", "CODE"],
    &["-s", "S1"],
    &["-o", "S1", "S2"],
    &["-ovi", "S1", "S2"],
    &["--", "S1"],
    &["-", "S1"],
    &["+c", "CODE"],
];

const PYTHON_MARKER: &str =
    "# marker\nimport os\nopen(os.environ['NN_DIFF_OUT'], 'a').write('NAME\\n')\n";
const PYTHON_CODE: &str = "import os; open(os.environ['NN_DIFF_OUT'], 'a').write('C\\n')";
const PYTHON_VOCAB: &[&str] = &[
    "S1",
    "S2",
    "S3",
    "S1",
    "S2",
    "CODE",
    "-O",
    "-OO",
    "-B",
    "-E",
    "-I",
    "-s",
    "-S",
    "-u",
    "-b",
    "-q",
    "-d",
    "-R",
    "-P",
    "-W",
    "ignore",
    "-Wignore",
    "-X",
    "dev",
    "-Xdev",
    "-c",
    "-Ic",
    "-m",
    "m1",
    "-x",
    "--",
    "-",
    "--check-hash-based-pycs",
    "always",
    "-i",
    "-V",
    "--version",
    "-h",
];
const PYTHON_FIXED: &[&[&str]] = &[
    &["-O", "S1", "S2"],
    &["-W", "S1", "S2"],
    &["-X", "dev", "S1"],
    &["-c", "CODE", "S1"],
    &["-Ic", "CODE", "S1"],
    &["-m", "m1", "S1"],
    &["-OO", "-B", "S2"],
    &["--", "S1"],
];

const PERL_MARKER: &str = "#!perl\nopen(my $f, '>>', $ENV{NN_DIFF_OUT}); print $f \"NAME\\n\";\n";
const PERL_CODE: &str = "open(my $f, '>>', $ENV{NN_DIFF_OUT}); print $f \"C\\n\";";
const PERL_VOCAB: &[&str] = &[
    "S1", "S2", "S3", "S1", "S2", "CODE", "-w", "-W", "-X", "-e", "-E", "-l", "-l0", "-n", "-p",
    "-a", "-s", "-x", "-i", "-i.bak", "-I", "-Itmp", "-Mstrict", "-mstrict", "-M", "-c", "-T",
    "-t", "-u", "-U", "-0", "-00", "-0777", "-CSD", "-F:", "-lane", "-le", "--", "-", "-v",
];
const PERL_FIXED: &[&[&str]] = &[
    &["-e", "CODE", "S1"],
    &["-lane", "CODE", "S1"],
    &["-I", "S1", "S2"],
    &["-Mstrict", "S1"],
    &["-x", "S1"],
    &["-CSD", "-E", "CODE"],
    &["--", "S1"],
];

const INTERPRETERS: &[Interp] = &[
    Interp {
        exe: "/usr/bin/bash",
        argv0: "bash",
        marker: SHELL_MARKER,
        code: SHELL_CODE,
        vocab: SHELL_VOCAB,
        fixed: SHELL_FIXED,
    },
    Interp {
        exe: "/usr/bin/dash",
        argv0: "sh",
        marker: SHELL_MARKER,
        code: SHELL_CODE,
        vocab: SHELL_VOCAB,
        fixed: SHELL_FIXED,
    },
    Interp {
        exe: "/bin/busybox",
        argv0: "sh",
        marker: SHELL_MARKER,
        code: SHELL_CODE,
        vocab: SHELL_VOCAB,
        fixed: SHELL_FIXED,
    },
    Interp {
        exe: "/usr/bin/zsh",
        argv0: "zsh",
        marker: SHELL_MARKER,
        code: SHELL_CODE,
        vocab: SHELL_VOCAB,
        fixed: SHELL_FIXED,
    },
    Interp {
        exe: "/usr/bin/mksh",
        argv0: "mksh",
        marker: SHELL_MARKER,
        code: SHELL_CODE,
        vocab: SHELL_VOCAB,
        fixed: SHELL_FIXED,
    },
    Interp {
        exe: "/usr/bin/python3",
        argv0: "python3",
        marker: PYTHON_MARKER,
        code: PYTHON_CODE,
        vocab: PYTHON_VOCAB,
        fixed: PYTHON_FIXED,
    },
    Interp {
        exe: "/usr/bin/perl",
        argv0: "perl",
        marker: PERL_MARKER,
        code: PERL_CODE,
        vocab: PERL_VOCAB,
        fixed: PERL_FIXED,
    },
];

/// Generated argvs per interpreter.
const GENERATED: usize = 1500;

/// What one argv ran: the names its markers appended.
fn run(i: &Interp, dir: &Path, tokens: &[&str]) -> (Vec<String>, Vec<String>) {
    let out = dir.join("out");
    let _ = std::fs::remove_file(&out);
    // fresh markers: an option may edit them (`perl -i`)
    for n in ["S1", "S2", "S3"] {
        std::fs::write(dir.join(n), i.marker.replace("NAME", n)).unwrap();
    }
    let args: Vec<String> = tokens
        .iter()
        .map(|t| match *t {
            "S1" | "S2" | "S3" => dir.join(t).to_string_lossy().into_owned(),
            "CODE" => i.code.to_string(),
            "tmp" | "-Itmp" => t.replace("tmp", &dir.to_string_lossy()),
            other => other.to_string(),
        })
        .collect();
    let mut child = Command::new(i.exe)
        .arg0(i.argv0)
        .args(&args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", dir)
        .env("NN_DIFF_OUT", &out)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let mut text = String::new();
    if let Ok(mut f) = std::fs::File::open(&out) {
        f.read_to_string(&mut text).unwrap();
    }
    // the names alone: `perl -l` adds a newline (`-l0` a NUL) to each print
    let mut ran: Vec<String> = text
        .lines()
        .map(|l| l.trim_matches(|c: char| c == '\0' || c.is_whitespace()))
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect();
    ran.sort();
    ran.dedup();
    let mut argv = vec![i.argv0.to_string()];
    argv.extend(args);
    (ran, argv)
}

/// Whether what ran agrees with the reading; `None`: not judged (Unknown).
fn agrees(runs: &Runs, ran: &[String], dir: &Path) -> Option<bool> {
    let name_of = |p: &str| {
        Path::new(p)
            .strip_prefix(dir)
            .ok()
            .map(|n| n.to_string_lossy().into_owned())
    };
    Some(match runs {
        Runs::Script(p) => match name_of(p) {
            Some(n) => ran.iter().all(|r| *r == n),
            None => ran.is_empty(),
        },
        Runs::Code => ran.iter().all(|r| r == "C"),
        Runs::Inline => ran.is_empty(),
        Runs::Unknown(_) => return None,
    })
}

#[test]
#[ignore = "runs the real interpreters (thousands of processes): NN_DIFF_INTERPRETERS=1"]
fn the_option_tables_agree_with_the_real_interpreters() {
    if std::env::var_os("NN_DIFF_INTERPRETERS").is_none() {
        eprintln!("NN_DIFF_INTERPRETERS is not set: nothing run");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let dir: PathBuf = dir.path().canonicalize().unwrap();
    let mut report: BTreeMap<&str, (usize, usize, usize)> = BTreeMap::new();
    let mut mismatches = Vec::new();
    for i in INTERPRETERS {
        if !Path::new(i.exe).exists() {
            eprintln!("{}: not installed, skipped", i.exe);
            continue;
        }
        let mut g = Gen(0x9e37_79b9_7f4a_7c15 ^ i.exe.len() as u64);
        let mut cases: Vec<Vec<&str>> = i.fixed.iter().map(|c| c.to_vec()).collect();
        for _ in 0..GENERATED {
            let n = 1 + (g.next() % 5) as usize;
            cases.push((0..n).map(|_| g.pick(i.vocab)).collect());
        }
        let (mut judged, mut unknown) = (0, 0);
        for tokens in &cases {
            let (ran, argv) = run(i, &dir, tokens);
            let runs = ExecIdentity::of_exec(i.exe, &argv).runs;
            match agrees(&runs, &ran, &dir) {
                None => unknown += 1,
                Some(true) => judged += 1,
                Some(false) => {
                    judged += 1;
                    mismatches.push(format!("{} {tokens:?}: read {runs:?}, ran {ran:?}", i.exe));
                }
            }
        }
        report.insert(i.exe, (cases.len(), judged, unknown));
    }
    for (exe, (n, judged, unknown)) in &report {
        eprintln!("{exe}: {n} argvs, {judged} judged, {unknown} Unknown (not judged)");
    }
    assert!(!report.is_empty(), "no interpreter found");
    assert!(
        mismatches.is_empty(),
        "{} argv(s) whose reading is not what ran:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
