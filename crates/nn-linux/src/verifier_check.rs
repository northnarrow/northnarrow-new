//! Lab only: `northnarrow-agent --verifier-check` (feature `debug-trigger`,
//! the lab build's; `deploy/lab/nn-lab.sh verifier-check`).
//!
//! Loads the embedded eBPF object the way the agent does at boot — the
//! multiplexer's loader (no CO-RE BTF, the exploit guard's task maps sized
//! as the agent sizes them), the `BTF_OFFSETS` table resolved from this
//! kernel's BTF, armed and frozen — then puts every program of the object
//! through `BPF_PROG_LOAD`, with the attach target its ELF section names
//! (`lsm/<hook>`, `fentry/<function>`, `tp_btf/<tracepoint>`; kprobes,
//! uprobes and tracepoints need none at load). Nothing is attached: the programs and
//! maps go away with the process. Maps the object pins by name land in
//! [`PIN_DIR`], away from the agent's pin root, and are removed at the end.
//!
//! Per program one line: `OK` with the translated and verified instruction
//! counts and the stack it uses (read back from the kernel's translated
//! image: the deepest frame, and the deepest call chain the way the verifier
//! adds it up against its 512-byte limit), or `REFUSED` with the verifier's
//! verdict. For a refused program the last [`TAIL_LINES`] lines of its full
//! verifier log are printed, and the whole log is kept in a private
//! directory (`/var/tmp/nn-verifier-check.XXXXXX`, printed on the
//! `verifier logs:` line) for the lab to copy back.
//!
//! The verdict is read in two passes. Up to 6.3 the kernel keeps the
//! *beginning* of a verifier log that does not fit the buffer (`ENOSPC`):
//! the instruction trace of a program that runs into the complexity limit is
//! larger than any buffer aya grows to (16 MiB), so its tail is where the
//! buffer ran out, not the error. The first pass therefore loads with
//! statistics only (`BPF_LOG_STATS`: the error, the instructions processed,
//! the stack depth of every subprogram — a few lines), the second, for the
//! refused programs only, with the full trace.
//!
//! Exit 0 when every program the agent needs loads, 1 when one is refused
//! (or its attach target is missing where the agent requires it), 2 when the
//! run could not start (not root, no object, BTF unusable). Programs that do
//! not count: the sensor-feasibility probes (`probe_*`, lab only), and an
//! optional deny hook (`anti_tamper::OPTIONAL_DENY_HOOKS`) this kernel does
//! not have.
//!
//! Lab knobs (environment): `NN_VERIFIER_CHECK_OBJECT=<file>` loads that
//! object instead of the embedded one (to iterate on the eBPF half without
//! rebuilding the agent); `NN_VERIFIER_CHECK_ONLY=<name,…>` loads only the
//! programs named.

use std::collections::BTreeMap;
use std::ffi::{CString, OsString};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use aya::programs::{Program, ProgramError};
use aya::{Btf, BtfError, Ebpf, EbpfLoader, VerifierLogLevel};
use sha2::{Digest, Sha256};

use crate::anti_tamper::btf_revalidate::{self, RefuseReason, ResolveOutcome};
use crate::anti_tamper::OPTIONAL_DENY_HOOKS;
use crate::sensors::ebpf_object::EBPF_BYTES;

/// Maps the object pins by name land here, away from the agent's pin root.
const PIN_DIR: &str = "/sys/fs/bpf/nn-verifier-check";
/// The full verifier logs go in a fresh `<base>/<prefix>.XXXXXX` (`mkdtemp`).
const LOG_BASE: &str = "/var/tmp";
const LOG_PREFIX: &str = "nn-verifier-check";
/// Lines of a refused program's verifier log printed in the report.
const TAIL_LINES: usize = 40;
/// The sensor-feasibility probes (`agent-ebpf/src/sensor_probe.rs`): loaded
/// by `--sensor-feasibility` only, never by the agent.
const LAB_PROBE_PREFIX: &str = "probe_";
const OBJECT_ENV: &str = "NN_VERIFIER_CHECK_OBJECT";
const ONLY_ENV: &str = "NN_VERIFIER_CHECK_ONLY";
/// The verifier's limit on the stack of a call chain (`MAX_BPF_STACK`).
const MAX_BPF_STACK: u32 = 512;

/// Run the check and print the report; the process exit code.
pub fn run() -> i32 {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("verifier-check: needs root (it loads eBPF programs)");
        return 2;
    }
    match execute() {
        Ok(true) => 0,
        Ok(false) => 1,
        Err(e) => {
            eprintln!("verifier-check: {e:#}");
            let _ = fs::remove_dir_all(PIN_DIR);
            2
        }
    }
}

/// What one load of one program came to.
enum Outcome {
    Loaded {
        insns: Option<u32>,
        verified: Option<u32>,
        stack: Option<Stack>,
    },
    /// The attach target is not in this kernel's BTF (aya refuses before
    /// `BPF_PROG_LOAD`).
    Absent(String),
    /// `BPF_PROG_LOAD` failed: errno and the verifier's log.
    Refused { errno: Option<i32>, log: String },
    /// Anything else (unexpected program type, a map error, …).
    Error(String),
}

/// Stack use read back from the translated image.
struct Stack {
    /// The deepest single frame (bytes).
    frame: u32,
    /// The deepest call chain, each frame rounded up to 32 bytes as the
    /// verifier counts it against [`MAX_BPF_STACK`].
    chain: u32,
}

struct Row {
    name: String,
    section: String,
    outcome: Outcome,
    /// `Some(why)` when the program does not count towards the exit code.
    optional: Option<String>,
}

impl Row {
    fn verdict(&self) -> &'static str {
        match (&self.outcome, &self.optional) {
            (Outcome::Loaded { .. }, _) => "OK",
            (Outcome::Absent(_), Some(_)) => "ABSENT",
            (Outcome::Absent(_), None) => "MISSING",
            (Outcome::Refused { .. }, Some(_)) => "REFUSED (does not count)",
            (Outcome::Refused { .. }, None) => "REFUSED",
            (Outcome::Error(_), Some(_)) => "ERROR (does not count)",
            (Outcome::Error(_), None) => "ERROR",
        }
    }

    fn counts_as_failure(&self) -> bool {
        self.optional.is_none() && !matches!(self.outcome, Outcome::Loaded { .. })
    }
}

fn execute() -> Result<bool> {
    let kernel = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    let (object, source) = object_bytes()?;
    let bytes = object.as_bytes();
    let sections = program_sections(bytes).context("reading the object's program sections")?;
    let only: Option<Vec<String>> = std::env::var(ONLY_ENV)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.split(',').map(|n| n.trim().to_string()).collect());

    println!("# eBPF verifier check — kernel {kernel}");
    println!();
    println!(
        "object: {source}, sha256 {}, {} bytes, {} programs",
        hex::encode(Sha256::digest(bytes)),
        bytes.len(),
        sections.len()
    );

    // The agent's boot: offsets from this kernel's BTF, published for
    // `arm_btf_offsets` (the agent refuses to start on a drift; so does this).
    match btf_revalidate::resolve_offsets() {
        ResolveOutcome::Resolved(r) => {
            println!(
                "offsets: {} slots resolved from the live BTF ({} differ from the build kernel, {} absent)",
                r.values.len(),
                r.drifted.len(),
                r.absent.len()
            );
            btf_revalidate::publish_resolved(r);
        }
        ResolveOutcome::SkippedNoBtf { reason } => {
            bail!("no vmlinux BTF ({reason}): the agent's LSM programs cannot load here")
        }
        ResolveOutcome::Refuse(RefuseReason::Drift(missing)) => bail!(
            "{} kernel field(s) missing on this kernel (the agent refuses to start): {}",
            missing.len(),
            missing
                .iter()
                .map(|m| format!("{}.{}", m.struct_name, m.name))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        ResolveOutcome::Refuse(RefuseReason::ParseError(e)) => {
            bail!("vmlinux BTF unparseable: {e}")
        }
    }
    let btf = Btf::from_sys_fs().context("loading the vmlinux BTF")?;

    // Pass 1: every program, statistics-only logs.
    let mut rows = Vec::new();
    {
        let mut ebpf = load_object(bytes, VerifierLogLevel::STATS)?;
        let names: Vec<String> = ebpf.programs().map(|(n, _)| n.to_string()).collect();
        for name in names {
            if only.as_ref().is_some_and(|o| !o.contains(&name)) {
                continue;
            }
            let section = sections.get(&name).cloned().unwrap_or_default();
            let outcome = match ebpf.program_mut(&name) {
                Some(p) => load_one(p, &section, &btf),
                None => Outcome::Error("not in the loaded object".into()),
            };
            let optional = optional_reason(&name, &section, &outcome);
            rows.push(Row {
                name,
                section,
                outcome,
                optional,
            });
        }
    }
    let _ = fs::remove_dir_all(PIN_DIR);

    // Pass 2: the refused ones again, full verifier trace.
    let refused: Vec<usize> = (0..rows.len())
        .filter(|&i| matches!(rows[i].outcome, Outcome::Refused { .. }))
        .collect();
    let mut traces: BTreeMap<String, (Option<i32>, String)> = BTreeMap::new();
    if !refused.is_empty() {
        let mut ebpf = load_object(bytes, VerifierLogLevel::DEBUG | VerifierLogLevel::STATS)?;
        for &i in &refused {
            let name = rows[i].name.clone();
            if let Some(p) = ebpf.program_mut(&name) {
                if let Outcome::Refused { errno, log } = load_one(p, &rows[i].section, &btf) {
                    traces.insert(name, (errno, log));
                }
            }
        }
    }
    let _ = fs::remove_dir_all(PIN_DIR);
    let log_dir = if refused.is_empty() {
        None
    } else {
        match private_dir(Path::new(LOG_BASE), LOG_PREFIX) {
            Ok(d) => Some(d),
            Err(e) => {
                println!("verifier logs: not kept ({e:#})");
                None
            }
        }
    };

    print_table(&rows);
    for &i in &refused {
        let row = &rows[i];
        let Outcome::Refused { errno, log } = &row.outcome else {
            continue;
        };
        println!();
        println!("## {} {} ({})", row.verdict(), row.name, row.section);
        println!();
        println!("errno: {}", errno_name(*errno));
        println!("verdict (statistics-only log):");
        for l in log.lines().filter(|l| !l.trim().is_empty()) {
            println!("    {l}");
        }
        if let Some((terrno, trace)) = traces.get(&row.name) {
            let lines: Vec<&str> = trace.lines().collect();
            let truncated = *terrno == Some(libc::ENOSPC);
            println!(
                "full verifier log: {} lines{}; last {}:",
                lines.len(),
                if truncated {
                    " — TRUNCATED by the kernel (ENOSPC, this kernel keeps the beginning): \
                     the tail below is where the buffer ran out, the verdict is the one above"
                } else {
                    ""
                },
                TAIL_LINES.min(lines.len())
            );
            for l in &lines[lines.len().saturating_sub(TAIL_LINES)..] {
                println!("    {l}");
            }
            if let Some(dir) = &log_dir {
                let stats = dir.join(format!("{}.stats.log", row.name));
                let full = dir.join(format!("{}.log", row.name));
                if let Err(e) = write_new(&stats, log).and_then(|()| write_new(&full, trace)) {
                    println!("(log not kept: {e:#})");
                }
            }
        }
    }
    if let Some(dir) = &log_dir {
        println!();
        println!("verifier logs: {}", dir.display());
    }

    let failures: Vec<&Row> = rows.iter().filter(|r| r.counts_as_failure()).collect();
    println!();
    println!(
        "== verifier-check {kernel}: {} programs, {} OK, {} not counted, {} failing{}",
        rows.len(),
        rows.iter()
            .filter(|r| matches!(r.outcome, Outcome::Loaded { .. }))
            .count(),
        rows.iter()
            .filter(|r| r.optional.is_some() && !matches!(r.outcome, Outcome::Loaded { .. }))
            .count(),
        failures.len(),
        if failures.is_empty() {
            String::new()
        } else {
            format!(
                ": {}",
                failures
                    .iter()
                    .map(|r| r.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    );
    Ok(failures.is_empty())
}

/// The object to check: the embedded one, or [`OBJECT_ENV`]'s file (copied
/// into 8-byte-aligned memory: aya's ELF parser reads aligned structures).
fn object_bytes() -> Result<(Aligned, String)> {
    match std::env::var_os(OBJECT_ENV) {
        Some(path) => {
            let path = PathBuf::from(path);
            let raw = fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            Ok((Aligned::copy_of(&raw), path.display().to_string()))
        }
        None => {
            if EBPF_BYTES.is_empty() {
                bail!("no eBPF object embedded (cargo xtask build-ebpf, then rebuild)");
            }
            Ok((Aligned::copy_of(EBPF_BYTES), "embedded".into()))
        }
    }
}

struct Aligned {
    words: Vec<u64>,
    len: usize,
}

impl Aligned {
    fn copy_of(bytes: &[u8]) -> Self {
        let mut words = vec![0u64; bytes.len().div_ceil(8)];
        for (w, chunk) in words.iter_mut().zip(bytes.chunks(8)) {
            let mut b = [0u8; 8];
            b[..chunk.len()].copy_from_slice(chunk);
            *w = u64::from_ne_bytes(b);
        }
        Self {
            words,
            len: bytes.len(),
        }
    }

    fn as_bytes(&self) -> &[u8] {
        // SAFETY: `words` holds at least `len` initialised bytes and lives
        // as long as the returned slice's borrow of `self`.
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast::<u8>(), self.len) }
    }
}

/// The agent's loader (`SensorMultiplexer::do_start`), with this run's own
/// pin directory, then `BTF_OFFSETS` armed and frozen as at boot.
fn load_object(bytes: &[u8], level: VerifierLogLevel) -> Result<Ebpf> {
    let _ = fs::remove_dir_all(PIN_DIR);
    fs::create_dir_all(PIN_DIR).with_context(|| format!("creating {PIN_DIR}"))?;
    let mut loader = EbpfLoader::new();
    loader.btf(None);
    let task_maps = crate::sensors::epg::TaskMaps::default();
    loader.map_max_entries(crate::sensors::epg::STRICT_TASKS_MAP, task_maps.strict);
    loader.map_max_entries(crate::sensors::epg::LITE_TASKS_MAP, task_maps.lite);
    loader.default_map_pin_directory(PIN_DIR);
    loader.verifier_log_level(level);
    let mut ebpf = loader
        .load(bytes)
        .context("loading the eBPF object (BTF, maps)")?;
    btf_revalidate::arm_btf_offsets(&mut ebpf).context("arming BTF_OFFSETS")?;
    btf_revalidate::freeze_btf_offsets(&ebpf).context("freezing BTF_OFFSETS")?;
    Ok(ebpf)
}

/// `BPF_PROG_LOAD` one program with the attach target its section names.
fn load_one(prog: &mut Program, section: &str, btf: &Btf) -> Outcome {
    let target = section.split_once('/').map_or("", |(_, t)| t);
    let r = match prog {
        Program::Lsm(p) => p.load(target, btf),
        Program::FEntry(p) => p.load(target, btf),
        Program::FExit(p) => p.load(target, btf),
        Program::BtfTracePoint(p) => p.load(target, btf),
        Program::KProbe(p) => p.load(),
        // Lab PR 229: the DNS sensor's uprobe on systemd-resolved's NSS module.
        Program::UProbe(p) => p.load(),
        Program::TracePoint(p) => p.load(),
        Program::RawTracePoint(p) => p.load(),
        other => {
            return Outcome::Error(format!(
                "program type {:?} is not one the agent loads",
                other.prog_type()
            ))
        }
    };
    match r {
        Ok(()) => {
            let info = prog.info().ok();
            let stack = prog
                .fd()
                .ok()
                .and_then(|fd| stack_of(fd.as_fd().as_raw_fd()));
            Outcome::Loaded {
                insns: info
                    .as_ref()
                    .and_then(|i| i.size_translated())
                    .map(|b| b / 8),
                verified: info.as_ref().and_then(|i| i.verified_instruction_count()),
                stack,
            }
        }
        Err(ProgramError::LoadError {
            io_error,
            verifier_log,
        }) => Outcome::Refused {
            errno: io_error.raw_os_error(),
            log: verifier_log.to_string(),
        },
        Err(ProgramError::Btf(BtfError::UnknownBtfTypeName { type_name })) => {
            Outcome::Absent(type_name)
        }
        Err(e) => Outcome::Error(chain(&e)),
    }
}

/// Why a program does not count towards the exit code, if it does not.
fn optional_reason(name: &str, section: &str, outcome: &Outcome) -> Option<String> {
    if name.starts_with(LAB_PROBE_PREFIX) {
        return Some("sensor-feasibility probe, never loaded by the agent".into());
    }
    if let Outcome::Absent(_) = outcome {
        let hook = section.strip_prefix("lsm/").unwrap_or("");
        if OPTIONAL_DENY_HOOKS.contains(&hook) {
            return Some(format!(
                "optional deny hook: this kernel has no `{hook}` (docs/operator/KERNEL_COMPATIBILITY.md)"
            ));
        }
    }
    None
}

fn print_table(rows: &[Row]) {
    println!();
    println!("| program | section | result | insns | verified | stack frame / chain | note |");
    println!("|---|---|---|---:|---:|---|---|");
    for r in rows {
        let (insns, verified, stack, note) = match &r.outcome {
            Outcome::Loaded {
                insns,
                verified,
                stack,
            } => (
                opt(*insns),
                opt(*verified),
                stack.as_ref().map_or_else(
                    || "n/a".to_string(),
                    |s| format!("{} / {} of {MAX_BPF_STACK}", s.frame, s.chain),
                ),
                r.optional.clone().unwrap_or_default(),
            ),
            Outcome::Refused { errno, log } => {
                let (processed, depth) = stats_of(log);
                (
                    "-".into(),
                    processed.unwrap_or_else(|| "-".into()),
                    depth.map_or_else(|| "-".into(), |d| format!("depths {d}")),
                    format!(
                        "{}{}",
                        r.optional
                            .as_ref()
                            .map_or_else(String::new, |o| format!("{o}; ")),
                        first_error(log).unwrap_or_else(|| errno_name(*errno))
                    ),
                )
            }
            Outcome::Absent(t) => (
                "-".into(),
                "-".into(),
                "-".into(),
                format!(
                    "no `{t}` in this kernel's BTF{}",
                    r.optional
                        .as_ref()
                        .map_or_else(String::new, |o| format!("; {o}"))
                ),
            ),
            Outcome::Error(e) => ("-".into(), "-".into(), "-".into(), e.clone()),
        };
        println!(
            "| {} | {} | {} | {} | {} | {} | {} |",
            r.name,
            r.section,
            r.verdict(),
            insns,
            verified,
            stack,
            note.replace('|', "/")
        );
    }
}

fn opt(v: Option<u32>) -> String {
    v.map_or_else(|| "n/a".into(), |n| n.to_string())
}

/// `processed N insns` and `stack depth a+b+…` of a statistics log.
fn stats_of(log: &str) -> (Option<String>, Option<String>) {
    let processed = log.lines().find_map(|l| {
        l.strip_prefix("processed ")
            .and_then(|r| r.split_whitespace().next())
            .map(str::to_string)
    });
    let depth = log
        .lines()
        .find_map(|l| l.strip_prefix("stack depth ").map(|d| d.trim().to_string()));
    (processed, depth)
}

/// The verifier's verdict: the last line of the log that is not a statistic.
fn first_error(log: &str) -> Option<String> {
    log.lines()
        .rev()
        .map(str::trim)
        .find(|l| {
            !l.is_empty()
                && !l.starts_with("processed ")
                && !l.starts_with("stack depth ")
                && !l.starts_with("verification time ")
        })
        .map(str::to_string)
}

fn errno_name(errno: Option<i32>) -> String {
    match errno {
        Some(libc::EACCES) => "EACCES (the verifier refused it)".into(),
        Some(libc::EINVAL) => "EINVAL".into(),
        Some(libc::E2BIG) => "E2BIG (too large)".into(),
        Some(libc::ENOSPC) => "ENOSPC (verifier log full)".into(),
        Some(libc::EPERM) => "EPERM".into(),
        Some(n) => format!("errno {n}"),
        None => "no errno".into(),
    }
}

fn chain(e: &dyn std::error::Error) -> String {
    let mut s = e.to_string();
    let mut cur = e.source();
    while let Some(c) = cur {
        s.push_str(": ");
        s.push_str(&c.to_string());
        cur = c.source();
    }
    s
}

// ───────────────────────── the object's sections ─────────────────────────

/// Program name (its function symbol) → the name of its ELF section, for
/// every global function in an executable section other than `.text`
/// (aya's programs; `.text` holds the subprograms).
fn program_sections(elf: &[u8]) -> Result<BTreeMap<String, String>> {
    const SHT_SYMTAB: u32 = 2;
    const SHF_EXECINSTR: u64 = 0x4;
    const STT_FUNC: u8 = 2;
    const STB_LOCAL: u8 = 0;
    if elf.get(..4) != Some(b"\x7fELF".as_slice()) || elf.get(4) != Some(&2) {
        bail!("not a 64-bit ELF object");
    }
    let shoff = le_u64(elf, 0x28)? as usize;
    let shentsize = le_u16(elf, 0x3a)? as usize;
    let shnum = le_u16(elf, 0x3c)? as usize;
    let shstrndx = le_u16(elf, 0x3e)? as usize;
    struct Sh {
        name: u32,
        kind: u32,
        flags: u64,
        offset: usize,
        size: usize,
        link: usize,
    }
    let mut shs = Vec::with_capacity(shnum);
    for i in 0..shnum {
        let b = shoff + i * shentsize;
        shs.push(Sh {
            name: le_u32(elf, b)?,
            kind: le_u32(elf, b + 4)?,
            flags: le_u64(elf, b + 8)?,
            offset: le_u64(elf, b + 24)? as usize,
            size: le_u64(elf, b + 32)? as usize,
            link: le_u32(elf, b + 40)? as usize,
        });
    }
    let strtab = |sh: &Sh, off: u32| -> Result<String> {
        let start = sh.offset + off as usize;
        let rest = elf
            .get(start..sh.offset + sh.size)
            .ok_or_else(|| anyhow!("string out of its table"))?;
        let end = rest.iter().position(|&c| c == 0).unwrap_or(rest.len());
        Ok(String::from_utf8_lossy(&rest[..end]).into_owned())
    };
    let shstr = shs
        .get(shstrndx)
        .ok_or_else(|| anyhow!("no section-name table"))?;
    let names: Vec<String> = shs
        .iter()
        .map(|s| strtab(shstr, s.name))
        .collect::<Result<_>>()?;
    let mut out = BTreeMap::new();
    for sym_sh in shs.iter().filter(|s| s.kind == SHT_SYMTAB) {
        let str_sh = shs
            .get(sym_sh.link)
            .ok_or_else(|| anyhow!("symbol table without strings"))?;
        for k in 0..sym_sh.size / 24 {
            let b = sym_sh.offset + k * 24;
            let info = *elf.get(b + 4).ok_or_else(|| anyhow!("short symbol"))?;
            let shndx = le_u16(elf, b + 6)? as usize;
            if info & 0xf != STT_FUNC || info >> 4 == STB_LOCAL {
                continue;
            }
            let Some(sec) = shs.get(shndx) else { continue };
            let sec_name = &names[shndx];
            if sec.flags & SHF_EXECINSTR == 0 || sec_name == ".text" {
                continue;
            }
            out.insert(strtab(str_sh, le_u32(elf, b)?)?, sec_name.clone());
        }
    }
    Ok(out)
}

fn le_u16(b: &[u8], at: usize) -> Result<u16> {
    let s = b.get(at..at + 2).ok_or_else(|| anyhow!("ELF too short"))?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn le_u32(b: &[u8], at: usize) -> Result<u32> {
    let s = b.get(at..at + 4).ok_or_else(|| anyhow!("ELF too short"))?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn le_u64(b: &[u8], at: usize) -> Result<u64> {
    let s = b.get(at..at + 8).ok_or_else(|| anyhow!("ELF too short"))?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Ok(u64::from_le_bytes(a))
}

// ───────────────────────── stack, from the kernel ─────────────────────────

/// `BPF_OBJ_GET_INFO_BY_FD`.
const OBJ_GET_INFO_BY_FD: libc::c_long = 15;
/// `struct bpf_prog_info` up to `nr_line_info` (every kernel since 5.0).
const INFO_LEN: usize = 152;
const OFF_XLATED_LEN: usize = 20;
const OFF_XLATED_INSNS: usize = 32;
const OFF_FUNC_INFO_REC_SIZE: usize = 132;
const OFF_FUNC_INFO: usize = 136;
const OFF_NR_FUNC_INFO: usize = 144;

#[repr(C)]
struct InfoAttr {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

fn prog_info(fd: i32, info: &mut [u8; INFO_LEN]) -> bool {
    let attr = InfoAttr {
        bpf_fd: fd as u32,
        info_len: INFO_LEN as u32,
        info: info.as_mut_ptr() as u64,
    };
    // SAFETY: a valid attr of its exact size; `info` is writable for
    // `INFO_LEN` bytes and every array it points to was sized from the
    // kernel's own counts.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            OBJ_GET_INFO_BY_FD,
            &attr as *const InfoAttr as *const libc::c_void,
            std::mem::size_of::<InfoAttr>(),
        )
    };
    rc == 0
}

/// The stack the loaded program uses, from its translated instructions and
/// its function boundaries. `None` when the kernel does not hand the image
/// out (`kptr_restrict`, no `CAP_SYSLOG`).
fn stack_of(fd: i32) -> Option<Stack> {
    let mut info = [0u8; INFO_LEN];
    if !prog_info(fd, &mut info) {
        return None;
    }
    let xlated_len = u32::from_ne_bytes(info[OFF_XLATED_LEN..OFF_XLATED_LEN + 4].try_into().ok()?);
    let nr_funcs = u32::from_ne_bytes(
        info[OFF_NR_FUNC_INFO..OFF_NR_FUNC_INFO + 4]
            .try_into()
            .ok()?,
    );
    if xlated_len == 0 {
        return None;
    }
    let mut insns = vec![0u64; (xlated_len as usize).div_ceil(8)];
    let mut funcs = vec![[0u32; 2]; nr_funcs.max(1) as usize];
    let mut info = [0u8; INFO_LEN];
    info[OFF_XLATED_LEN..OFF_XLATED_LEN + 4].copy_from_slice(&xlated_len.to_ne_bytes());
    info[OFF_XLATED_INSNS..OFF_XLATED_INSNS + 8]
        .copy_from_slice(&(insns.as_mut_ptr() as u64).to_ne_bytes());
    if nr_funcs > 0 {
        info[OFF_NR_FUNC_INFO..OFF_NR_FUNC_INFO + 4].copy_from_slice(&nr_funcs.to_ne_bytes());
        info[OFF_FUNC_INFO_REC_SIZE..OFF_FUNC_INFO_REC_SIZE + 4]
            .copy_from_slice(&8u32.to_ne_bytes());
        info[OFF_FUNC_INFO..OFF_FUNC_INFO + 8]
            .copy_from_slice(&(funcs.as_mut_ptr() as u64).to_ne_bytes());
    }
    if !prog_info(fd, &mut info) {
        return None;
    }
    // The kernel zeroes the pointer when it does not dump the image.
    if info[OFF_XLATED_INSNS..OFF_XLATED_INSNS + 8] == [0u8; 8] {
        return None;
    }
    let starts: Vec<usize> = if nr_funcs == 0 {
        vec![0]
    } else {
        funcs.iter().map(|f| f[0] as usize).collect()
    };
    let raw: Vec<[u8; 8]> = insns.iter().map(|w| w.to_ne_bytes()).collect();
    Some(stack_estimate(&raw, &starts))
}

/// Per-function stack depth (the deepest `r10 - off` the function touches,
/// directly or through a pointer it derives from `r10`) and the deepest call
/// chain, frames rounded up to 32 bytes the way `check_max_stack_depth`
/// adds them.
fn stack_estimate(insns: &[[u8; 8]], starts: &[usize]) -> Stack {
    let func_of = |i: usize| starts.iter().rposition(|&s| s <= i).unwrap_or(0);
    let mut depth = vec![0u32; starts.len()];
    let mut calls: Vec<Vec<usize>> = vec![Vec::new(); starts.len()];
    let mut from_fp = [false; 11];
    let mut i = 0;
    while i < insns.len() {
        if starts.contains(&i) {
            from_fp = [false; 11];
        }
        let b = insns[i];
        let code = b[0];
        let dst = (b[1] & 0x0f) as usize;
        let src = (b[1] >> 4) as usize;
        let off = i16::from_le_bytes([b[2], b[3]]) as i64;
        let imm = i32::from_le_bytes([b[4], b[5], b[6], b[7]]) as i64;
        let f = func_of(i);
        let mut deeper = |d: i64| {
            if d > 0 && d as u32 > depth[f] {
                depth[f] = d as u32;
            }
        };
        let class = code & 0x07;
        let mode = code & 0xe0;
        match class {
            // LDX: a load from the stack, or a register overwritten.
            0x01 => {
                if src == 10 {
                    deeper(-off);
                }
                if dst < 11 {
                    from_fp[dst] = false;
                }
            }
            // ST / STX (memory and atomics): a store to the stack.
            0x02 | 0x03 if mode == 0x60 || mode == 0xc0 => {
                if dst == 10 {
                    deeper(-off);
                }
            }
            // ALU64: `rX = r10`, `rX += -N`.
            0x07 => {
                if dst < 11 {
                    if code == 0x07 && from_fp[dst] {
                        deeper(-imm);
                    } else {
                        // `rX = r10`, or a copy of such a pointer.
                        from_fp[dst] = code == 0xbf && (src == 10 || (src < 11 && from_fp[src]));
                    }
                }
            }
            0x04 => {
                if dst < 11 {
                    from_fp[dst] = false;
                }
            }
            // JMP: a pseudo call to a subprogram (`imm` before JIT, `off`
            // once the JIT has rewritten `imm` to the subprogram's index).
            0x05 if code == 0x85 => {
                if src == 1 {
                    let by_off = (i as i64 + off + 1) as usize;
                    let by_imm = (i as i64 + imm + 1) as usize;
                    let target = if starts.contains(&by_off) {
                        Some(by_off)
                    } else if starts.contains(&by_imm) {
                        Some(by_imm)
                    } else {
                        None
                    };
                    if let Some(t) = target.and_then(|t| starts.iter().position(|&s| s == t)) {
                        calls[f].push(t);
                    }
                }
                for r in from_fp.iter_mut().take(6) {
                    *r = false;
                }
            }
            _ => {}
        }
        // `ld_imm64` takes two slots; a callback (`src` 4) is a frame too.
        if code == 0x18 {
            if src == 4 {
                let t = (i as i64 + imm + 1) as usize;
                if let Some(t) = starts.iter().position(|&s| s == t) {
                    calls[f].push(t);
                }
            }
            if dst < 11 {
                from_fp[dst] = false;
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    let frame = depth.iter().copied().max().unwrap_or(0);
    let mut memo = vec![None; starts.len()];
    let chain = chain_depth(0, &depth, &calls, &mut memo, 0);
    Stack { frame, chain }
}

fn chain_depth(
    f: usize,
    depth: &[u32],
    calls: &[Vec<usize>],
    memo: &mut [Option<u32>],
    level: usize,
) -> u32 {
    if let Some(d) = memo[f] {
        return d;
    }
    // The verifier allows 8 frames; a cycle cannot load at all.
    if level > 8 {
        return 0;
    }
    let own = depth[f].max(1).div_ceil(32) * 32;
    let mut deepest = 0;
    for &c in &calls[f] {
        if c != f {
            deepest = deepest.max(chain_depth(c, depth, calls, memo, level + 1));
        }
    }
    let d = own + deepest;
    memo[f] = Some(d);
    d
}

// ───────────────────────── the log directory ─────────────────────────

/// A directory made by `mkdtemp(3)`: new, private (0700), unpredictable.
fn private_dir(base: &Path, prefix: &str) -> Result<PathBuf> {
    let template = base.join(format!("{prefix}.XXXXXX"));
    let mut buf =
        CString::new(template.into_os_string().into_encoded_bytes())?.into_bytes_with_nul();
    // SAFETY: a writable NUL-terminated template that outlives the call;
    // mkdtemp rewrites the trailing `XXXXXX` in place.
    if unsafe { libc::mkdtemp(buf.as_mut_ptr().cast()) }.is_null() {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("mkdtemp under {}", base.display()));
    }
    buf.pop();
    Ok(PathBuf::from(OsString::from_vec(buf)))
}

/// Write a new file (`O_CREAT|O_EXCL`, never through a link), mode 0600.
fn write_new(path: &Path, text: &str) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(text.as_bytes())
        .with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
        let o = off.to_le_bytes();
        let m = imm.to_le_bytes();
        [code, (src << 4) | dst, o[0], o[1], m[0], m[1], m[2], m[3]]
    }

    /// A stack store, a pointer derived from r10 and a call to a subprogram
    /// with a frame of its own: the deepest frame and the chain as the
    /// verifier rounds it.
    #[test]
    fn stack_estimate_reads_frames_and_the_call_chain() {
        let insns = [
            insn(0x7b, 10, 1, -40, 0),  // *(u64 *)(r10 - 40) = r1
            insn(0xbf, 2, 10, 0, 0),    // r2 = r10
            insn(0x07, 2, 0, 0, -72),   // r2 += -72
            insn(0x85, 0, 1, 0, 2),     // call pc+2 (subprogram at 6)
            insn(0xb7, 0, 0, 0, 0),     // r0 = 0
            insn(0x95, 0, 0, 0, 0),     // exit
            insn(0x7a, 10, 0, -200, 0), // *(u64 *)(r10 - 200) = 0
            insn(0x95, 0, 0, 0, 0),     // exit
        ];
        let s = stack_estimate(&insns, &[0, 6]);
        assert_eq!(s.frame, 200);
        // main 72 → 96, subprogram 200 → 224.
        assert_eq!(s.chain, 96 + 224);
    }

    /// After the JIT the kernel dumps a pseudo call with the subprogram's
    /// index in `imm` and the relative offset in `off`.
    #[test]
    fn stack_estimate_follows_a_jited_call() {
        let insns = [
            insn(0x85, 0, 1, 1, 1), // call (off 1 → insn 2; imm = subprog 1)
            insn(0x95, 0, 0, 0, 0),
            insn(0x63, 10, 1, -8, 0), // *(u32 *)(r10 - 8) = r1
            insn(0x95, 0, 0, 0, 0),
        ];
        let s = stack_estimate(&insns, &[0, 2]);
        assert_eq!(s.chain, 32 + 32);
    }

    #[test]
    fn stats_and_verdict_of_a_statistics_log() {
        let log = "reg type unsupported for arg#0 function f#37\n\
                   Unreleased reference id=4 alloc_insn=12\n\
                   verification time 1200 usec\n\
                   stack depth 120+32+0\n\
                   processed 4321 insns (limit 1000000) max_states_per_insn 4 total_states 90 peak_states 90 mark_read 9\n";
        let (p, d) = stats_of(log);
        assert_eq!(p.as_deref(), Some("4321"));
        assert_eq!(d.as_deref(), Some("120+32+0"));
        assert_eq!(
            first_error(log).as_deref(),
            Some("Unreleased reference id=4 alloc_insn=12")
        );
    }

    /// The object's sections name every program's attach target (an
    /// embedded build only).
    #[test]
    fn program_sections_of_the_embedded_object() {
        if EBPF_BYTES.is_empty() {
            return;
        }
        let s = program_sections(EBPF_BYTES).expect("the object's sections");
        assert_eq!(
            s.get("epg_lite_commit_creds").map(String::as_str),
            Some("fentry/commit_creds")
        );
        assert_eq!(
            s.get("exec_check_lsm").map(String::as_str),
            Some("lsm/bprm_check_security")
        );
        assert!(
            !s.keys().any(|k| k.starts_with("nn_")),
            "subprograms in .text are not programs"
        );
    }

    #[test]
    fn probes_and_absent_optional_hooks_do_not_count() {
        let absent = Outcome::Absent("bpf_lsm_inode_set_acl".into());
        assert!(optional_reason("protected_set_acl_deny", "lsm/inode_set_acl", &absent).is_some());
        assert!(optional_reason("task_kill", "lsm/task_kill", &absent).is_none());
        let refused = Outcome::Refused {
            errno: Some(libc::EACCES),
            log: String::new(),
        };
        assert!(optional_reason("probe_bprm", "lsm/bprm_check_security", &refused).is_some());
        assert!(optional_reason("exec_check_lsm", "lsm/bprm_check_security", &refused).is_none());
    }
}
