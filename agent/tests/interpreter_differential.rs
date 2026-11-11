//! Lot 310 (external bug hunt, edition 1.4; the triage's move 3, first
//! stage): the interpreters' option tables of `posture::script_args`,
//! checked against the real interpreters.
//!
//! For each interpreter present on the host (bash, dash, python3, perl;
//! busybox, zsh, mksh, node and ruby when installed) a fixed corpus of
//! argvs — the spellings of the three hunts (BUG-42, BUG-44, BUG-97,
//! BUG-99, BUG-100) and of the review of #539 — and a few thousand
//! generated from a vocabulary of its options (some of them two options in
//! one argument, `-i -e`: perl reads on after a space) and of three marker
//! scripts, with a deterministic generator (no dependency). Each argv runs
//! the real interpreter in a temporary directory, its home the directory,
//! its standard input a fourth marker program (`STDIN`): an argv the
//! interpreter reads its standard input for shows. Each marker and the
//! inline program append their name to a file when they run. What ran is
//! then compared with the reading ([`Runs`]):
//!
//! - `Script(p)`, `p` a marker: `p` ran, and nothing else; `p` no marker (a
//!   word the generator made, `x`): nothing ran;
//! - `Code` with the inline program the generator wrote: it ran (a module
//!   the argv loads may run beside it: `Code` vouches for nothing); with
//!   another text: it did not; with none (an option that loads the
//!   caller's code, then the standard input): something ran;
//! - `Inline` (nothing named): nothing ran, or the standard input's
//!   program alone (a shell or a REPL reading it: the exec pump's
//!   `STDIN_PROGRAM` reads it as code);
//! - `Unknown`: anything (no trust is given) — counted, not judged.
//!
//! Nothing ran for a confident reading that names a marker or the inline
//! program is a mismatch (the interpreter refused the argv: the reading
//! must say `Unknown`). A mismatch is an identity a caller could move: the
//! reading names a script the interpreter did not run, or misses one it
//! ran.
//!
//! `#[ignore]` and a no-op without `NN_DIFF_INTERPRETERS=1`: it runs
//! thousands of processes. Run it on a lab guest (`cargo test -p
//! northnarrow-agent --test interpreter_differential -- --ignored` with the
//! variable set, or the test binary copied there) or on a developer's
//! host; it writes only in its temporary directory. (In the agent's tests:
//! nn-core is a pure crate, its tests reach no OS interface.)

use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use northnarrow_agent::posture::lineage::{ExecIdentity, Runs};
use northnarrow_agent::posture::script_args::inline_program;

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
    /// What its standard input holds: the marker named `STDIN`.
    stdin: &'static str,
    code: &'static str,
    vocab: &'static [&'static str],
    fixed: &'static [&'static [&'static str]],
}

const SHELL_MARKER: &str = "printf 'NAME\\n' >> \"$NN_DIFF_OUT\"\n";
const SHELL_CODE: &str = "printf 'C\\n' >> \"$NN_DIFF_OUT\"";
const SHELL_STDIN: &str = "printf 'STDIN\\n' >> \"$NN_DIFF_OUT\"\n";
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
    "-e -x",
    "-o vi",
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
    // the review of #539 (finding 10): dash's `-posix` is `-p -o six`…
    &["-posix", "vi", "-c", "CODE"],
    &["-o", "vi", "-c", "CODE"],
    &["-o", "nosuchname", "S1"],
    &["-O", "extglob", "S1"],
    &["-s", "S1", "S2"],
    &["-i"],
];

const PYTHON_MARKER: &str =
    "# marker\nimport os\nopen(os.environ['NN_DIFF_OUT'], 'a').write('NAME\\n')\n";
const PYTHON_CODE: &str = "import os; open(os.environ['NN_DIFF_OUT'], 'a').write('C\\n')";
const PYTHON_STDIN: &str = "import os; open(os.environ['NN_DIFF_OUT'], 'a').write('STDIN\\n')\n";
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
    "-O -B",
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
    &["-i", "S1"],
    &["-"],
    &["-W", "", "S1"],
];

const PERL_MARKER: &str = "#!perl\nopen(my $f, '>>', $ENV{NN_DIFF_OUT}); print $f \"NAME\\n\";\n";
const PERL_CODE: &str = "open(my $f, '>>', $ENV{NN_DIFF_OUT}); print $f \"C\\n\";";
const PERL_STDIN: &str = "open(my $f, '>>', $ENV{NN_DIFF_OUT}); print $f \"STDIN\\n\";\n";
const PERL_VOCAB: &[&str] = &[
    "S1",
    "S2",
    "S3",
    "S1",
    "S2",
    "CODE",
    "-w",
    "-W",
    "-X",
    "-e",
    "-E",
    "-l",
    "-l0",
    "-n",
    "-p",
    "-a",
    "-s",
    "-x",
    "-i",
    "-i.bak",
    "-I",
    "-Itmp",
    "-Mstrict",
    "-mstrict",
    "-M",
    "-c",
    "-T",
    "-t",
    "-u",
    "-U",
    "-0",
    "-00",
    "-0777",
    "-CSD",
    "-F:",
    "-lane",
    "-le",
    "--",
    "-",
    "-v",
    "-i -e",
    "-i.bak -e",
    "-F: -e",
    "-C -e",
    "-l -n",
    "-w -x",
    "-i -I",
    "-D",
    "-n -e",
];
const PERL_FIXED: &[&[&str]] = &[
    &["-e", "CODE", "S1"],
    &["-lane", "CODE", "S1"],
    &["-I", "S1", "S2"],
    &["-Mstrict", "S1"],
    &["-x", "S1"],
    &["-CSD", "-E", "CODE"],
    &["--", "S1"],
    // the review of #539 (finding 1): perl reads on after a space
    &["-i -e", "CODE", "S1"],
    &["-F: -e", "CODE", "S1"],
    &["-C -e", "CODE", "S1"],
    &["-i.bak -w", "S1"],
    &["-MS1", "S2"],
    &["-c", "S1"],
];

const NODE_MARKER: &str = "require('fs').appendFileSync(process.env.NN_DIFF_OUT, 'NAME\\n');\n";
const NODE_CODE: &str = "require('fs').appendFileSync(process.env.NN_DIFF_OUT, 'C\\n')";
const NODE_STDIN: &str = "require('fs').appendFileSync(process.env.NN_DIFF_OUT, 'STDIN\\n');\n";
const NODE_VOCAB: &[&str] = &[
    "S1",
    "S2",
    "S3",
    "S1",
    "S2",
    "CODE",
    "x",
    "-e",
    "--eval",
    "-p",
    "--print",
    "-c",
    "--check",
    "-i",
    "--interactive",
    "-r",
    "--require",
    "--import",
    "--no-warnings",
    "--no-deprecation",
    "--stack-size=500",
    "--max-old-space-size=64",
    "--enable-source-maps",
    "--trace-warnings",
    "--title",
    "t",
    "--input-type=commonjs",
    "-v",
    "--version",
    "-h",
    "--",
    "-",
];
const NODE_FIXED: &[&[&str]] = &[
    &["-e", "CODE", "S1"],
    &["-r", "S1", "S2"],
    &["--require", "S1", "S2"],
    &["--import", "S1", "S2"],
    &["--title", "S1", "S2"],
    &["--no-warnings", "S1"],
    &["-c", "S1"],
    &["--", "S1"],
    &["-"],
];

const RUBY_MARKER: &str = "File.open(ENV['NN_DIFF_OUT'], 'a') { |f| f.puts 'NAME' }\n";
const RUBY_CODE: &str = "File.open(ENV['NN_DIFF_OUT'], 'a') { |f| f.puts 'C' }";
const RUBY_STDIN: &str = "File.open(ENV['NN_DIFF_OUT'], 'a') { |f| f.puts 'STDIN' }\n";
const RUBY_VOCAB: &[&str] = &[
    "S1",
    "S2",
    "S3",
    "S1",
    "S2",
    "CODE",
    "x",
    "-e",
    "-w",
    "-W0",
    "-W",
    "-v",
    "--version",
    "-c",
    "-n",
    "-p",
    "-l",
    "-a",
    "-r",
    "-I",
    "-Itmp",
    "-x",
    "-s",
    "-E",
    "UTF-8",
    "--disable-gems",
    "--disable=gems",
    "-Ku",
    "-0",
    "-F:",
    "-C",
    "tmp",
    "-h",
    "--",
    "-",
];
const RUBY_FIXED: &[&[&str]] = &[
    &["-e", "CODE", "S1"],
    &["-r", "S1", "S2"],
    &["-I", "S1", "S2"],
    &["-C", "tmp", "S1"],
    &["-E", "UTF-8", "S1"],
    &["-c", "S1"],
    &["-v", "S1"],
    &["-x", "S1"],
    &["--", "S1"],
];

const INTERPRETERS: &[Interp] = &[
    Interp {
        exe: "/usr/bin/bash",
        argv0: "bash",
        marker: SHELL_MARKER,
        stdin: SHELL_STDIN,
        code: SHELL_CODE,
        vocab: SHELL_VOCAB,
        fixed: SHELL_FIXED,
    },
    Interp {
        exe: "/usr/bin/dash",
        argv0: "sh",
        marker: SHELL_MARKER,
        stdin: SHELL_STDIN,
        code: SHELL_CODE,
        vocab: SHELL_VOCAB,
        fixed: SHELL_FIXED,
    },
    Interp {
        exe: "/bin/busybox",
        argv0: "sh",
        marker: SHELL_MARKER,
        stdin: SHELL_STDIN,
        code: SHELL_CODE,
        vocab: SHELL_VOCAB,
        fixed: SHELL_FIXED,
    },
    Interp {
        exe: "/usr/bin/zsh",
        argv0: "zsh",
        marker: SHELL_MARKER,
        stdin: SHELL_STDIN,
        code: SHELL_CODE,
        vocab: SHELL_VOCAB,
        fixed: SHELL_FIXED,
    },
    Interp {
        exe: "/usr/bin/mksh",
        argv0: "mksh",
        marker: SHELL_MARKER,
        stdin: SHELL_STDIN,
        code: SHELL_CODE,
        vocab: SHELL_VOCAB,
        fixed: SHELL_FIXED,
    },
    Interp {
        exe: "/usr/bin/python3",
        argv0: "python3",
        marker: PYTHON_MARKER,
        stdin: PYTHON_STDIN,
        code: PYTHON_CODE,
        vocab: PYTHON_VOCAB,
        fixed: PYTHON_FIXED,
    },
    Interp {
        exe: "/usr/bin/perl",
        argv0: "perl",
        marker: PERL_MARKER,
        stdin: PERL_STDIN,
        code: PERL_CODE,
        vocab: PERL_VOCAB,
        fixed: PERL_FIXED,
    },
    Interp {
        exe: "/usr/bin/node",
        argv0: "node",
        marker: NODE_MARKER,
        stdin: NODE_STDIN,
        code: NODE_CODE,
        vocab: NODE_VOCAB,
        fixed: NODE_FIXED,
    },
    Interp {
        exe: "/usr/bin/ruby",
        argv0: "ruby",
        marker: RUBY_MARKER,
        stdin: RUBY_STDIN,
        code: RUBY_CODE,
        vocab: RUBY_VOCAB,
        fixed: RUBY_FIXED,
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
    let stdin = dir.join("stdin");
    std::fs::write(&stdin, i.stdin).unwrap();
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
        .stdin(Stdio::from(std::fs::File::open(&stdin).unwrap()))
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
fn agrees(
    i: &Interp,
    exe: &Path,
    argv: &[String],
    runs: &Runs,
    ran: &[String],
    dir: &Path,
) -> Option<bool> {
    let marker = |p: &Path| {
        p.strip_prefix(dir)
            .ok()
            .map(|n| n.to_string_lossy().into_owned())
            .filter(|n| ["S1", "S2", "S3"].contains(&n.as_str()))
    };
    let only = |want: &str| ran.len() == 1 && ran[0] == want;
    Some(match runs {
        Runs::Script(p) => match marker(Path::new(&**p)) {
            Some(n) => only(&n),
            None => ran.is_empty(),
        },
        Runs::Code => match inline_program(exe, argv) {
            Some(prog) if prog == i.code => ran.iter().any(|r| r == "C"),
            Some(_) => !ran.iter().any(|r| r == "C"),
            None => !ran.is_empty(),
        },
        Runs::Inline => ran.is_empty() || only("STDIN"),
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
            // the file the kernel opened, as the LSM program names it
            let exe = std::fs::canonicalize(i.exe).unwrap();
            let runs = ExecIdentity::of_exec(&exe.to_string_lossy(), &argv).runs;
            match agrees(i, &exe, &argv, &runs, &ran, &dir) {
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
