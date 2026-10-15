//! Tappa 10.9, step 0 — sensor-feasibility runner.
//!
//! `northnarrow-agent --sensor-feasibility`, in lab builds only (feature
//! `test-privileged`); `deploy/lab/nn-lab.sh sensor-feasibility` stops the
//! installed agent, runs it and starts the agent again. It loads the
//! throw-away probes of `agent-ebpf/src/sensor_probe.rs` on the running
//! kernel, exercises each one from this process and prints a Markdown
//! report: per program, whether the verifier accepted it (instruction count
//! where the kernel reports it) and whether it attached; the new kernel
//! offsets read from the live BTF; one line per property that
//! `docs/design/TAPPA10_9_SENSOR_ATTACH_POINTS_DESIGN.md` relies on.
//!
//! Exit 0 when every required property holds, 1 when one does not, 2 when
//! the run could not start (not root, no embedded eBPF object). The probes
//! only look at this process and its children: nothing else on the host is
//! observed or slowed down. The fixtures live in a fresh directory
//! `/var/tmp/nn-feasibility.XXXXXX` made by `mkdtemp(3)` (mode 0700, a name
//! no one can predict); `NN_FEASIBILITY_BASE=<dir>` puts it under `<dir>`
//! instead, to run the file checks on another filesystem. The tmpfs exec
//! case copies `/usr/bin/true` into another such directory under `/dev/shm`.
//! The runner runs as root: it never creates, removes or executes a file at
//! a fixed name in a world-writable directory (external audit SNS-003).

use std::ffi::{CString, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::UdpSocket;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{anyhow, bail, Context, Result};
use aya::maps::{Array, HashMap, MapData, RingBuf};
use aya::programs::{FExit, KProbe, Lsm, ProgramError, ProgramInfo};
use aya::{Btf, Ebpf, EbpfLoader};
use common::wire::sensor_probe::{
    probe_slot, SensorProbeRaw, PROBE_DETAIL_LEN, PROBE_KIND_ANCESTOR, PROBE_KIND_DIR,
    PROBE_KIND_DNS4, PROBE_KIND_DNS6, PROBE_KIND_EXEC, PROBE_KIND_MASS_WRITE, PROBE_KIND_NAME,
    PROBE_KIND_UDP_SEND_SKB, PROBE_MASS_WRITE_MIN, PROBE_OFFSETS_MAGIC, PROBE_PATH_SLOTS,
    PROBE_PATH_SLOT_LEN,
};
use common::wire::InodeKey;

use crate::anti_tamper::btf_revalidate::{self, RefuseReason, ResolveOutcome};
use crate::anti_tamper::filesystem::{stat_dev_to_kernel_dev, AyaInodeKey};
use crate::sensors::ebpf_object::EBPF_BYTES;
use crate::telemetry_probe::dns_query_packet;

const VMLINUX_BTF: &str = "/sys/kernel/btf/vmlinux";
/// Maps the object pins by name land here, away from the agent's pin root.
const PIN_DIR: &str = "/sys/fs/bpf/nn-feasibility";
/// Fixtures go in a fresh `<base>/nn-feasibility.XXXXXX` (`mkdtemp`);
/// `NN_FEASIBILITY_BASE` moves it to another filesystem. Only that
/// directory, made by this run, is ever removed.
const WORK_BASE: &str = "/var/tmp";
const WORK_PREFIX: &str = "nn-feasibility";
/// The tmpfs exec case: `/usr/bin/true` copied into a fresh
/// `/dev/shm/nn-feasibility.XXXXXX/true`.
const SHM_BASE: &str = "/dev/shm";
/// Owner every file the runner executes must have (it runs as root).
const ROOT_UID: u32 = 0;
const TRUE_BIN: &str = "/usr/bin/true";
const DNS_NAME: &str = "nn-feasibility.example";
const TOCTOU_OPENS: usize = 200;
/// Opens between two drains: 40 records fit the probes' 64 KiB ring.
const TOCTOU_BATCH: usize = 40;
const MASS_WRITE_OPENS: u32 = PROBE_MASS_WRITE_MIN + 5;
const TMPFS_MAGIC: u64 = 0x0102_1994;
const S_IFMT: u32 = 0o170_000;
const S_IFREG: u32 = 0o100_000;
const FMODE_READ: u32 = 0x1;
/// `MFD_EXEC` (6.3+); older kernels refuse the flag with `EINVAL`.
const MFD_EXEC: libc::c_uint = 0x10;
const NAME_LEN: usize = 32;

/// The probes' own offsets, written into `PROBE_OFFSETS` from the live BTF.
const PROBE_FIELDS: [(u32, &str, &[&str]); 8] = [
    (probe_slot::SUPER_BLOCK_S_MAGIC, "super_block", &["s_magic"]),
    (probe_slot::INODE_I_NLINK, "inode", &["i_nlink"]),
    (probe_slot::INODE_I_MODE, "inode", &["i_mode"]),
    (probe_slot::LINUX_BINPRM_FILE, "linux_binprm", &["file"]),
    (
        probe_slot::LINUX_BINPRM_FILENAME,
        "linux_binprm",
        &["filename"],
    ),
    (probe_slot::SK_BUFF_HEAD, "sk_buff", &["head"]),
    (
        probe_slot::SK_BUFF_TRANSPORT_HEADER,
        "sk_buff",
        &["transport_header"],
    ),
    (probe_slot::SK_BUFF_LEN, "sk_buff", &["len"]),
];

/// Run the probes and print the report; the process exit code.
pub fn run() -> i32 {
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("sensor-feasibility: needs root (it loads eBPF programs)");
        return 2;
    }
    if EBPF_BYTES.is_empty() {
        eprintln!(
            "sensor-feasibility: no eBPF object embedded (cargo xtask build-ebpf, then rebuild)"
        );
        return 2;
    }
    let _ = fs::remove_dir_all(PIN_DIR);
    let mut rep = Report {
        kernel: fs::read_to_string("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".into()),
        ..Report::default()
    };
    let work = work_dir();
    let outcome = match &work {
        Ok(w) => execute(&mut rep, w.path()),
        Err(e) => Err(anyhow!("{e:#}")),
    };
    let _ = fs::remove_dir_all(PIN_DIR);
    // The programs are gone with the object: the baseline.
    if let (Some(n), Ok(w)) = (bench_opens_requested(), &work) {
        let path = w.path().join("unwatched/bench");
        if path.exists() {
            p_bench(&mut rep, "no program", &path, n);
        }
    }
    // Removes the fixtures' directory, and only it.
    drop(work);
    if let Err(e) = outcome {
        rep.check("the run completed", true, false, format!("{e:#}"));
    }
    rep.print();
    if rep.passed() {
        0
    } else {
        1
    }
}

/// The fixtures' directory, fresh and private: `<base>/nn-feasibility.XXXXXX`.
fn work_dir() -> Result<PrivateDir> {
    let base = std::env::var_os("NN_FEASIBILITY_BASE")
        .map_or_else(|| PathBuf::from(WORK_BASE), PathBuf::from);
    // A BASE that does not exist would silently put the fixtures on the
    // root filesystem instead of the one being tested.
    if !base.is_dir() {
        bail!("NN_FEASIBILITY_BASE {} is not a directory", base.display());
    }
    PrivateDir::create(&base, WORK_PREFIX)
}

/// A directory made by `mkdtemp(3)`: created by this call (never one that
/// already existed), under a name no one can predict, mode 0700 and owned by
/// this process's user. Removed with its contents on drop.
struct PrivateDir(PathBuf);

impl PrivateDir {
    fn create(base: &Path, prefix: &str) -> Result<Self> {
        let template = base.join(format!("{prefix}.XXXXXX"));
        let mut buf =
            CString::new(template.into_os_string().into_encoded_bytes())?.into_bytes_with_nul();
        // SAFETY: `buf` is a writable, NUL-terminated template that outlives
        // the call; mkdtemp only rewrites the trailing `XXXXXX` in place.
        if unsafe { libc::mkdtemp(buf.as_mut_ptr().cast()) }.is_null() {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("mkdtemp under {}", base.display()));
        }
        buf.pop();
        let dir = Self(PathBuf::from(OsString::from_vec(buf)));
        // mkdtemp made it with mode 0700; the umask can only narrow that.
        let m = fs::symlink_metadata(&dir.0)?;
        if !m.is_dir() || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 {
            bail!(
                "{} is not a private directory (mode {:o}, uid {})",
                dir.0.display(),
                m.mode() & 0o7777,
                m.uid()
            );
        }
        Ok(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Create `path`, which must not exist yet (`O_CREAT|O_EXCL`), never through
/// a symlink (`O_NOFOLLOW`).
fn create_private(path: &Path, mode: u32) -> std::io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(mode)
        .open(path)
}

/// Copy `/usr/bin/true` to `to`, a new file (0700). The writable descriptor
/// is closed on return, so the copy can be executed (no `ETXTBSY`).
fn copy_true(to: &Path) -> Result<()> {
    create_private(to, 0o700)
        .and_then(|mut f| f.write_all(&fs::read(TRUE_BIN)?))
        .with_context(|| format!("copying {TRUE_BIN} to {}", to.display()))
}

/// An error and its sources, `a: b: c` — the kernel's errno is usually the
/// last link.
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

fn execute(rep: &mut Report, work: &Path) -> Result<()> {
    // The probes reuse the production `BTF_OFFSETS` slots (file, dentry,
    // inode, task): arm them exactly as the agent does at boot.
    match btf_revalidate::resolve_offsets() {
        ResolveOutcome::Resolved(r) => {
            rep.notes.push(format!(
                "production offsets: {} slots resolved from the live BTF ({} differ from the build kernel, {} absent)",
                r.values.len(),
                r.drifted.len(),
                r.absent.len()
            ));
            btf_revalidate::publish_resolved(r);
        }
        ResolveOutcome::SkippedNoBtf { reason } => {
            bail!("no vmlinux BTF ({reason}): LSM programs cannot load here")
        }
        ResolveOutcome::Refuse(RefuseReason::Drift(missing)) => bail!(
            "production offsets: {} field(s) missing on this kernel: {}",
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

    let queries: Vec<(&str, &[&str])> = PROBE_FIELDS.iter().map(|(_, s, f)| (*s, *f)).collect();
    let resolved = btf_revalidate::resolve_fields_from(Path::new(VMLINUX_BTF), &queries)
        .map_err(|e| anyhow!("probe offsets: {e}"))?;
    let mut probe_offsets = Vec::new();
    let mut missing = Vec::new();
    for ((slot, st, path), r) in PROBE_FIELDS.iter().zip(resolved) {
        let field = format!("{st}.{}", path.join("."));
        match r {
            Ok(off) => {
                probe_offsets.push((*slot, off as u32));
                rep.offsets.push((field, off.to_string()));
            }
            Err(e) => {
                rep.offsets.push((field.clone(), format!("absent ({e})")));
                missing.push(field);
            }
        }
    }
    rep.check(
        "every new offset (inode, superblock, linux_binprm, sk_buff) resolves from the live BTF",
        true,
        missing.is_empty(),
        if missing.is_empty() {
            format!("{} fields", PROBE_FIELDS.len())
        } else {
            format!("missing: {}", missing.join(", "))
        },
    );

    let btf = Btf::from_sys_fs().context("loading the vmlinux BTF")?;
    fs::create_dir_all(PIN_DIR).with_context(|| format!("creating {PIN_DIR}"))?;
    let mut ebpf = EbpfLoader::new()
        .btf(None)
        .map_pin_path(PIN_DIR)
        .load(EBPF_BYTES)
        .context("loading the eBPF object (is the installed agent still running? stop it first)")?;
    btf_revalidate::arm_btf_offsets(&mut ebpf).context("arming BTF_OFFSETS")?;
    {
        let mut arr: Array<_, u32> = Array::try_from(
            ebpf.map_mut("PROBE_OFFSETS")
                .context("PROBE_OFFSETS missing")?,
        )?;
        for slot in 1..probe_slot::COUNT {
            arr.set(slot, u32::MAX, 0)?;
        }
        for (slot, off) in &probe_offsets {
            arr.set(*slot, *off, 0)?;
        }
        arr.set(probe_slot::MAGIC, PROBE_OFFSETS_MAGIC, 0)?;
    }

    let file_open = load_lsm(&mut ebpf, rep, "probe_file_open", "file_open", &btf);
    let bprm = load_lsm(&mut ebpf, rep, "probe_bprm", "bprm_check_security", &btf);
    let ret4 = load_kprobe(
        &mut ebpf,
        rep,
        "probe_ip_make_skb",
        "kretprobe",
        &["ip_make_skb"],
    );
    let ret6 = load_kprobe(
        &mut ebpf,
        rep,
        "probe_ip6_make_skb",
        "kretprobe",
        &["ip6_make_skb"],
    );
    let send = load_kprobe(
        &mut ebpf,
        rep,
        "probe_udp_send_skb",
        "kprobe",
        &["udp_send_skb", "udp_v6_send_skb"],
    );
    let fexit4 = load_fexit(
        &mut ebpf,
        rep,
        "probe_fexit_ip_make_skb",
        "ip_make_skb",
        &btf,
    );
    let fexit6 = load_fexit(
        &mut ebpf,
        rep,
        "probe_fexit_ip6_make_skb",
        "ip6_make_skb",
        &btf,
    );
    rep.check(
        "LSM file_open observer (parent lookup, name table, 8-level ancestor walk, LRU counter) loads and attaches",
        true,
        file_open,
        "see Programs",
    );
    rep.check(
        "LSM bprm_check_security reading linux_binprm loads and attaches",
        true,
        bprm,
        "see Programs",
    );
    rep.check(
        "fexit on ip_make_skb (10 arguments) / ip6_make_skb (9 arguments)",
        false,
        fexit4 && fexit6,
        format!(
            "ip_make_skb: {}, ip6_make_skb: {} — x86-64 trampolines took at most 6 arguments before 6.5",
            if fexit4 { "attached" } else { "refused" },
            if fexit6 { "attached" } else { "refused" }
        ),
    );

    let fx = Fixtures::create(work, Path::new(SHM_BASE)).context("creating the fixtures")?;
    rep.notes.push(format!(
        "fixtures under {} (filesystem magic {})",
        work.display(),
        crate::fs_type::magic_of_path(work)
            .map_or_else(|| "unknown".to_string(), |m| format!("{m:#x}"))
    ));
    let mut probes = Probes::new(ebpf)?;
    probes.fill_tables(&fx)?;
    probes.arm()?;

    if file_open {
        exercise_dir(&mut probes, rep, &fx)?;
        exercise_names(&mut probes, rep, &fx)?;
        exercise_toctou(&mut probes, rep, &fx)?;
        exercise_mass_write(&mut probes, rep, &fx)?;
    }
    if bprm {
        exercise_exec(&mut probes, rep, &fx)?;
    }
    exercise_dns(&mut probes, rep, &ret4, &ret6, &send)?;

    // Step 1 sizing: what the observer costs a non-matching open (every
    // check runs, the ancestor walk up to the root included).
    if let (Some(n), true) = (bench_opens_requested(), file_open) {
        let path = fx.path("unwatched/bench");
        fs::write(&path, b"x")?;
        probes.cache_dir(&fx.path("unwatched"))?;
        p_bench(
            rep,
            "full filter (open matches nothing; parent, name and 5-level ancestor checks)",
            &path,
            n,
        );
        probes.set_mode(2)?;
        p_bench(
            rep,
            "step 1 fast path: file key + lookup, parent key + cache hit",
            &path,
            n,
        );
        probes.set_mode(1)?;
        p_bench(
            rep,
            "file key + one lookup (today's FIM observer)",
            &path,
            n,
        );
        probes.set_mode(0)?;
        probes.disarm()?;
        p_bench(
            rep,
            "program attached, returns at once (not the target)",
            &path,
            n,
        );
    }

    probes.disarm()?;
    let stray = probes.drain();
    rep.check(
        "no record outside the exercises",
        false,
        probes.stray + stray.len() == 0,
        format!("{} stray record(s)", probes.stray + stray.len()),
    );
    Ok(())
}

// ───────────────────────────── loading ─────────────────────────────

fn load_lsm(
    ebpf: &mut Ebpf,
    rep: &mut Report,
    program: &'static str,
    hook: &str,
    btf: &Btf,
) -> bool {
    let point = format!("lsm/{hook}");
    let prog: &mut Lsm = match ebpf.program_mut(program).map(|p| p.try_into()) {
        Some(Ok(p)) => p,
        _ => return rep.missing(program, point),
    };
    if let Err(e) = prog.load(hook, btf) {
        return rep.rejected(program, point, &e);
    }
    let info = prog.info();
    let attached = prog
        .attach()
        .map(|_| String::from("yes"))
        .map_err(|e| chain(&e));
    rep.loaded(program, point, info, attached)
}

fn load_fexit(
    ebpf: &mut Ebpf,
    rep: &mut Report,
    program: &'static str,
    func: &str,
    btf: &Btf,
) -> bool {
    let point = format!("fexit/{func}");
    let prog: &mut FExit = match ebpf.program_mut(program).map(|p| p.try_into()) {
        Some(Ok(p)) => p,
        _ => return rep.missing(program, point),
    };
    if let Err(e) = prog.load(func, btf) {
        return rep.rejected(program, point, &e);
    }
    let info = prog.info();
    let attached = prog
        .attach()
        .map(|_| String::from("yes"))
        .map_err(|e| chain(&e));
    rep.loaded(program, point, info, attached)
}

/// Load a kprobe/kretprobe and attach it to each symbol, or to the
/// compiler's renamed copy of a static one (`udp_send_skb.isra.0`); the
/// symbols actually attached.
fn load_kprobe(
    ebpf: &mut Ebpf,
    rep: &mut Report,
    program: &'static str,
    kind: &str,
    symbols: &[&str],
) -> Vec<String> {
    let point = format!("{kind} {}", symbols.join(", "));
    let prog: &mut KProbe = match ebpf.program_mut(program).map(|p| p.try_into()) {
        Some(Ok(p)) => p,
        _ => {
            rep.missing(program, point);
            return Vec::new();
        }
    };
    if let Err(e) = prog.load() {
        rep.rejected(program, point, &e);
        return Vec::new();
    }
    let info = prog.info();
    let mut attached = Vec::new();
    let mut results = Vec::new();
    for sym in symbols {
        match attach_symbol(prog, sym) {
            Ok(used) => {
                results.push(if used == *sym {
                    format!("{sym}: yes")
                } else {
                    format!("{sym}: yes, as {used}")
                });
                attached.push(used);
            }
            Err(e) => results.push(format!("{sym}: no ({e})")),
        }
    }
    let all = attached.len() == symbols.len();
    let summary = results.join("; ");
    rep.loaded(
        program,
        point,
        info,
        if all { Ok(summary) } else { Err(summary) },
    );
    attached
}

fn attach_symbol(prog: &mut KProbe, symbol: &str) -> Result<String, String> {
    match prog.attach(symbol, 0) {
        Ok(_) => Ok(symbol.to_string()),
        Err(first) => {
            for alt in kallsyms_variants(symbol) {
                if prog.attach(&alt, 0).is_ok() {
                    return Ok(alt);
                }
            }
            Err(chain(&first))
        }
    }
}

/// `symbol.isra.0`, `symbol.constprop.0`, … listed in `/proc/kallsyms`.
fn kallsyms_variants(symbol: &str) -> Vec<String> {
    let prefix = format!("{symbol}.");
    let mut out: Vec<String> = fs::read_to_string("/proc/kallsyms")
        .map(|t| {
            t.lines()
                .filter_map(|l| l.split_whitespace().nth(2))
                .filter(|s| s.starts_with(&prefix))
                .map(String::from)
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out.dedup();
    out
}

// ───────────────────────────── fixtures ─────────────────────────────

/// Files the exercises open and execute, created before the probes are
/// armed so that setting up never shows in the records.
struct Fixtures {
    root: PathBuf,
    /// Deleted copy of `/usr/bin/true`, kept open (exec through `/proc`).
    deleted: File,
    /// Read-only descriptor of a memfd holding `/usr/bin/true`.
    memfd: Option<File>,
    memfd_note: String,
    /// `/usr/bin/true` copied to tmpfs, in its own private directory: held
    /// here so the copy lives until the exec case. Or why there is none.
    shm: std::result::Result<(PrivateDir, PathBuf), String>,
}

impl Fixtures {
    /// `root` is the private work directory; the tmpfs copy goes in a
    /// private directory of its own under `shm_base`.
    fn create(root: &Path, shm_base: &Path) -> Result<Self> {
        let root = root.to_path_buf();
        for d in [
            "watched",
            "unwatched",
            "home/.aws",
            "home/other",
            "home/profile",
            "home/.gnupg/private-keys-v1.d",
            "home/notgnupg",
        ] {
            fs::create_dir_all(root.join(d))?;
        }
        for f in [
            "watched/target",
            "watched/other",
            "plain",
            "home/.aws/credentials",
            "home/other/credentials",
            "home/profile/key4.db",
            "home/.gnupg/private-keys-v1.d/x.key",
            "home/notgnupg/x.key",
        ] {
            create_private(&root.join(f), 0o600)?.write_all(f.as_bytes())?;
        }
        let shm = PrivateDir::create(shm_base, WORK_PREFIX)
            .and_then(|dir| {
                let copy = dir.path().join("true");
                copy_true(&copy)?;
                Ok((dir, copy))
            })
            .map_err(|e| format!("{e:#}"));
        let del_path = root.join("deleted-true");
        copy_true(&del_path)?;
        let deleted = File::open(&del_path)?;
        fs::remove_file(&del_path)?;
        let (memfd, memfd_note) = match memfd_with_true() {
            Ok(f) => (Some(f), String::new()),
            Err(e) => (None, format!("{e:#}")),
        };
        Ok(Self {
            root,
            deleted,
            memfd,
            memfd_note,
            shm,
        })
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }
}

/// A memfd holding `/usr/bin/true`, reopened read-only (an open writable
/// descriptor would make the exec fail with `ETXTBSY`).
fn memfd_with_true() -> Result<File> {
    let name = CString::new("nn-feasibility")?;
    let mut fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | MFD_EXEC) };
    if fd < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
        fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    }
    if fd < 0 {
        bail!("memfd_create: {}", std::io::Error::last_os_error());
    }
    let mut rw = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    rw.write_all(&fs::read(TRUE_BIN)?)?;
    let ro = File::open(format!("/proc/self/fd/{}", rw.as_raw_fd()))?;
    drop(rw);
    Ok(ro)
}

// ───────────────────────────── probes ─────────────────────────────

struct Probes {
    ebpf: Ebpf,
    ring: RingBuf<MapData>,
    /// Records drained between exercises.
    stray: usize,
}

impl Probes {
    fn new(mut ebpf: Ebpf) -> Result<Self> {
        let ring = RingBuf::try_from(
            ebpf.take_map("PROBE_EVENTS")
                .context("PROBE_EVENTS missing")?,
        )?;
        Ok(Self {
            ebpf,
            ring,
            stray: 0,
        })
    }

    fn fill_tables(&mut self, fx: &Fixtures) -> Result<()> {
        let watched = fs::metadata(fx.path("watched"))?;
        let mut dirs: HashMap<_, AyaInodeKey, u8> = HashMap::try_from(
            self.ebpf
                .map_mut("PROBE_DIRS")
                .context("PROBE_DIRS missing")?,
        )?;
        dirs.insert(
            AyaInodeKey(InodeKey {
                dev: stat_dev_to_kernel_dev(watched.dev()),
                ino: watched.ino(),
            }),
            1,
            0,
        )?;
        let mut names: HashMap<_, [u8; 2 * NAME_LEN], u8> = HashMap::try_from(
            self.ebpf
                .map_mut("PROBE_NAMES")
                .context("PROBE_NAMES missing")?,
        )?;
        names.insert(name_key("credentials", Some(".aws")), 1, 0)?;
        names.insert(name_key("key4.db", None), 1, 0)?;
        let mut anc: HashMap<_, [u8; NAME_LEN], u8> = HashMap::try_from(
            self.ebpf
                .map_mut("PROBE_ANCESTORS")
                .context("PROBE_ANCESTORS missing")?,
        )?;
        anc.insert(name32(".gnupg"), 1, 0)?;
        Ok(())
    }

    fn set_target(&mut self, tgid: u32) -> Result<()> {
        let mut t: Array<_, u32> = Array::try_from(
            self.ebpf
                .map_mut("PROBE_TARGET")
                .context("PROBE_TARGET missing")?,
        )?;
        t.set(0, tgid, 0)?;
        Ok(())
    }

    fn arm(&mut self) -> Result<()> {
        self.set_target(std::process::id())
    }

    fn disarm(&mut self) -> Result<()> {
        self.set_target(0)
    }

    fn set_mode(&mut self, mode: u32) -> Result<()> {
        let mut m: Array<_, u32> = Array::try_from(
            self.ebpf
                .map_mut("PROBE_MODE")
                .context("PROBE_MODE missing")?,
        )?;
        m.set(0, mode, 0)?;
        Ok(())
    }

    /// Put `dir` in the step 1 classification cache (bench: a cache hit).
    fn cache_dir(&mut self, dir: &Path) -> Result<()> {
        let m = fs::metadata(dir)?;
        let mut c: HashMap<_, AyaInodeKey, u32> = HashMap::try_from(
            self.ebpf
                .map_mut("PROBE_DIR_CACHE")
                .context("PROBE_DIR_CACHE missing")?,
        )?;
        c.insert(
            AyaInodeKey(InodeKey {
                dev: stat_dev_to_kernel_dev(m.dev()),
                ino: m.ino(),
            }),
            0,
            0,
        )?;
        Ok(())
    }

    /// Forget this process's write-open window.
    fn reset_write_window(&mut self) -> Result<()> {
        let mut w: HashMap<_, u32, [u8; 16]> = HashMap::try_from(
            self.ebpf
                .map_mut("PROBE_WRITES")
                .context("PROBE_WRITES missing")?,
        )?;
        let _ = w.remove(&std::process::id());
        Ok(())
    }

    fn drain(&mut self) -> Vec<SensorProbeRaw> {
        let size = std::mem::size_of::<SensorProbeRaw>();
        let mut out = Vec::new();
        while let Some(item) = self.ring.next() {
            if item.len() >= size {
                out.push(bytemuck::pod_read_unaligned::<SensorProbeRaw>(
                    &item[..size],
                ));
            }
        }
        out
    }

    /// Start an exercise: whatever is in the ring now is stray.
    fn begin(&mut self) {
        let n = self.drain().len();
        self.stray += n;
    }
}

fn name32(s: &str) -> [u8; NAME_LEN] {
    let mut k = [0u8; NAME_LEN];
    let b = s.as_bytes();
    let n = b.len().min(NAME_LEN - 1);
    k[..n].copy_from_slice(&b[..n]);
    k
}

/// `PROBE_NAMES` key: leaf ‖ parent (zero = any parent).
fn name_key(leaf: &str, parent: Option<&str>) -> [u8; 2 * NAME_LEN] {
    let mut k = [0u8; 2 * NAME_LEN];
    k[..NAME_LEN].copy_from_slice(&name32(leaf));
    if let Some(p) = parent {
        k[NAME_LEN..].copy_from_slice(&name32(p));
    }
    k
}

fn components(r: &SensorProbeRaw) -> Vec<String> {
    (0..(r.path_n as usize).min(PROBE_PATH_SLOTS))
        .map(|i| {
            let slot = &r.path[i * PROBE_PATH_SLOT_LEN..(i + 1) * PROBE_PATH_SLOT_LEN];
            let end = slot.iter().position(|&b| b == 0).unwrap_or(slot.len());
            String::from_utf8_lossy(&slot[..end]).into_owned()
        })
        .collect()
}

/// Mount-relative path from the leaf → root components.
fn rendered_path(r: &SensorProbeRaw) -> String {
    let c = components(r);
    let parts: Vec<&str> = c
        .iter()
        .rev()
        .map(String::as_str)
        .filter(|s| *s != "/")
        .collect();
    let p = format!("/{}", parts.join("/"));
    if r.path_truncated != 0 {
        format!("…{p}")
    } else {
        p
    }
}

fn detail(r: &SensorProbeRaw) -> &[u8] {
    &r.detail[..(r.detail_len as usize).min(PROBE_DETAIL_LEN)]
}

fn kind_name(k: u8) -> &'static str {
    match k {
        PROBE_KIND_DIR => "dir",
        PROBE_KIND_NAME => "name",
        PROBE_KIND_ANCESTOR => "ancestor",
        PROBE_KIND_MASS_WRITE => "mass-write",
        PROBE_KIND_EXEC => "exec",
        PROBE_KIND_DNS4 => "dns4",
        PROBE_KIND_DNS6 => "dns6",
        PROBE_KIND_UDP_SEND_SKB => "udp_send_skb",
        _ => "?",
    }
}

fn kinds(evs: &[SensorProbeRaw]) -> String {
    if evs.is_empty() {
        return "none".into();
    }
    evs.iter()
        .map(|e| kind_name(e.kind))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Open read-only, return the opened file's identity and the records.
fn open_and_drain(p: &mut Probes, path: &Path) -> Result<(InodeKey, Vec<SensorProbeRaw>)> {
    let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let m = f.metadata()?;
    drop(f);
    Ok((
        InodeKey {
            dev: stat_dev_to_kernel_dev(m.dev()),
            ino: m.ino(),
        },
        p.drain(),
    ))
}

// ───────────────────────────── exercises ─────────────────────────────

fn exercise_dir(p: &mut Probes, rep: &mut Report, fx: &Fixtures) -> Result<()> {
    p.begin();
    let target = fx.path("watched/target");
    let (key, evs) = open_and_drain(p, &target)?;
    let ok = evs.len() == 1 && {
        let e = &evs[0];
        e.kind == PROBE_KIND_DIR
            && e.dev == key.dev
            && e.ino == key.ino
            && e.mode & FMODE_READ != 0
            && e.pid == std::process::id()
            && e.path_truncated == 0
            && target.to_string_lossy().ends_with(&rendered_path(e))
    };
    let ev = evs.first().map_or("no record".to_string(), |e| {
        format!(
            "{} (dev {:#x}, ino {}, path {})",
            kind_name(e.kind),
            e.dev,
            e.ino,
            rendered_path(e)
        )
    });
    rep.check(
        "file in a watched directory: one record, (dev, ino) of the file actually opened, mount-relative path",
        true,
        ok,
        format!("{ev}; expected dev {:#x}, ino {}", key.dev, key.ino),
    );
    let (_, evs) = open_and_drain(p, &fx.path("plain"))?;
    rep.check(
        "file outside every table: no record",
        true,
        evs.is_empty(),
        kinds(&evs),
    );
    Ok(())
}

fn exercise_names(p: &mut Probes, rep: &mut Report, fx: &Fixtures) -> Result<()> {
    p.begin();
    let (aws_key, aws) = open_and_drain(p, &fx.path("home/.aws/credentials"))?;
    let (_, other) = open_and_drain(p, &fx.path("home/other/credentials"))?;
    let (_, key4) = open_and_drain(p, &fx.path("home/profile/key4.db"))?;
    let leaf_is = |evs: &[SensorProbeRaw], kind: u8, leaf: &str| {
        evs.len() == 1
            && evs[0].kind == kind
            && components(&evs[0]).first().map(String::as_str) == Some(leaf)
    };
    rep.check(
        "name table: credentials under .aws matches, credentials under another directory does not",
        true,
        leaf_is(&aws, PROBE_KIND_NAME, "credentials") && other.is_empty(),
        format!(
            ".aws/credentials: {}; other/credentials: {}",
            kinds(&aws),
            kinds(&other)
        ),
    );
    // The name match does not depend on any key userland computed, so this
    // record shows the kernel's (dev, ino) as is: it must be what stat()
    // gives userland, or no inode table (watched paths, protected inodes)
    // can ever match on this filesystem.
    let identity = aws.first().map(|e| (e.dev, e.ino));
    rep.check(
        "the record's (dev, ino) is the identity userland computes with stat()",
        true,
        identity == Some((aws_key.dev, aws_key.ino)),
        match identity {
            Some((dev, ino)) => format!(
                "record dev {dev:#x} ino {ino}; stat() dev {:#x} ino {}",
                aws_key.dev, aws_key.ino
            ),
            None => "no record".to_string(),
        },
    );
    rep.check(
        "name table: key4.db matches under any parent",
        true,
        leaf_is(&key4, PROBE_KIND_NAME, "key4.db"),
        format!("profile/key4.db: {}", kinds(&key4)),
    );
    let (_, gpg) = open_and_drain(p, &fx.path("home/.gnupg/private-keys-v1.d/x.key"))?;
    let (_, not) = open_and_drain(p, &fx.path("home/notgnupg/x.key"))?;
    rep.check(
        "ancestor table: a file two levels under .gnupg matches, one under another directory does not",
        true,
        leaf_is(&gpg, PROBE_KIND_ANCESTOR, "x.key") && not.is_empty(),
        format!(".gnupg/…/x.key: {}; notgnupg/x.key: {}", kinds(&gpg), kinds(&not)),
    );
    Ok(())
}

/// A second thread swaps two files of the watched directory (renameat2
/// RENAME_EXCHANGE) while this one opens the same name: every record must
/// carry the inode the open returned.
fn exercise_toctou(p: &mut Probes, rep: &mut Report, fx: &Fixtures) -> Result<()> {
    p.begin();
    let a = CString::new(
        fx.path("watched/target")
            .into_os_string()
            .into_encoded_bytes(),
    )?;
    let b = CString::new(
        fx.path("watched/other")
            .into_os_string()
            .into_encoded_bytes(),
    )?;
    let stop = Arc::new(AtomicBool::new(false));
    let flips = Arc::new(AtomicU64::new(0));
    let flipper = {
        let (stop, flips) = (Arc::clone(&stop), Arc::clone(&flips));
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let r = unsafe {
                    libc::syscall(
                        libc::SYS_renameat2,
                        libc::AT_FDCWD,
                        a.as_ptr(),
                        libc::AT_FDCWD,
                        b.as_ptr(),
                        libc::RENAME_EXCHANGE,
                    )
                };
                if r == 0 {
                    flips.fetch_add(1, Ordering::Relaxed);
                }
            }
        })
    };
    let target = fx.path("watched/target");
    let mut opened = Vec::with_capacity(TOCTOU_OPENS);
    let mut recorded = Vec::with_capacity(TOCTOU_OPENS);
    let mut other_kinds = 0usize;
    let mut failure = None;
    for _ in 0..TOCTOU_OPENS / TOCTOU_BATCH {
        for _ in 0..TOCTOU_BATCH {
            match File::open(&target).and_then(|f| f.metadata()) {
                Ok(m) => opened.push(m.ino()),
                Err(e) => failure = Some(e.to_string()),
            }
        }
        for e in p.drain() {
            if e.kind == PROBE_KIND_DIR {
                recorded.push(e.ino);
            } else {
                other_kinds += 1;
            }
        }
    }
    stop.store(true, Ordering::Relaxed);
    let _ = flipper.join();
    let mismatched = opened.iter().zip(&recorded).filter(|(o, r)| o != r).count();
    let mut distinct = opened.clone();
    distinct.sort_unstable();
    distinct.dedup();
    rep.check(
        "TOCTOU: with the name swapped concurrently, each record names the inode the open returned",
        true,
        failure.is_none() && opened.len() == recorded.len() && mismatched == 0 && other_kinds == 0,
        format!(
            "{} opens, {} records, {} mismatched, {} other kinds, {} swaps, {} distinct inodes opened{}",
            opened.len(),
            recorded.len(),
            mismatched,
            other_kinds,
            flips.load(Ordering::Relaxed),
            distinct.len(),
            failure.map_or(String::new(), |e| format!(", open error: {e}"))
        ),
    );
    rep.check(
        "TOCTOU exercise actually raced (both inodes were opened)",
        false,
        distinct.len() >= 2,
        format!("{} distinct inodes", distinct.len()),
    );
    Ok(())
}

fn exercise_mass_write(p: &mut Probes, rep: &mut Report, fx: &Fixtures) -> Result<()> {
    p.begin();
    p.reset_write_window()?;
    let mut fired_at = Vec::new();
    let mut extra = Vec::new();
    for i in 1..=MASS_WRITE_OPENS {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(fx.path(&format!("unwatched/f{i:02}")))?;
        for e in p.drain() {
            if e.kind == PROBE_KIND_MASS_WRITE {
                fired_at.push(i);
            } else {
                extra.push(kind_name(e.kind));
            }
        }
    }
    rep.check(
        format!(
            "in-kernel write counter: one record at the {PROBE_MASS_WRITE_MIN}th write-open in the window, none before or after"
        ),
        true,
        fired_at == [PROBE_MASS_WRITE_MIN] && extra.is_empty(),
        format!(
            "{MASS_WRITE_OPENS} write-opens; mass-write record at open(s) {fired_at:?}; other records: {}",
            if extra.is_empty() { "none".to_string() } else { extra.join(", ") }
        ),
    );
    Ok(())
}

/// How a case starts its child.
enum Launch {
    /// `execve(path)` through `std::process::Command`.
    Path(String),
    /// `execveat(fd, "", AT_EMPTY_PATH)`, glibc's `fexecve`; the
    /// `sys_enter_execve` sensor of today never sees it.
    Execveat(i32),
}

/// The file a case executes, as checked just before the exec.
enum ExecTarget<'a> {
    /// A name: `lstat`, so a symlink is refused.
    Path(PathBuf),
    /// An open descriptor: `fstat`.
    File(&'a File),
}

/// Checked right before each exec, on the file itself: a regular file owned
/// by `owner` with exactly `nlink` links (1 for a copy this run made, so no
/// second name exists that someone else holds; 0 for a deleted file or a
/// memfd). A named file must also be writable by its owner only; a memfd is
/// 0777 by construction but has no name anyone could open it by.
fn vet_exec_target(target: &ExecTarget<'_>, owner: u32, nlink: u64) -> Result<(), String> {
    let m = match target {
        ExecTarget::Path(p) => fs::symlink_metadata(p),
        ExecTarget::File(f) => f.metadata(),
    }
    .map_err(|e| format!("stat: {e}"))?;
    if !m.file_type().is_file() {
        return Err("not a regular file".into());
    }
    if m.uid() != owner {
        return Err(format!("owned by uid {}, expected {owner}", m.uid()));
    }
    if m.nlink() != nlink {
        return Err(format!("{} link(s), expected {nlink}", m.nlink()));
    }
    if matches!(target, ExecTarget::Path(_)) && m.mode() & 0o022 != 0 {
        return Err(format!(
            "mode {:o} is writable by group or others",
            m.mode() & 0o7777
        ));
    }
    Ok(())
}

struct ExecCase<'a> {
    label: &'static str,
    launch: Launch,
    target: ExecTarget<'a>,
    /// `bprm->filename` as the kernel builds it.
    filename: String,
    expect_ino: u64,
    expect_dev: u64,
    /// The record must show `i_nlink == 0`.
    deleted: bool,
    /// The record must show the tmpfs superblock magic.
    tmpfs: bool,
}

fn exercise_exec(p: &mut Probes, rep: &mut Report, fx: &Fixtures) -> Result<()> {
    let me = std::process::id();
    let mut cases = Vec::new();
    let m = fs::metadata(TRUE_BIN)?;
    cases.push(ExecCase {
        label: "/usr/bin/true",
        launch: Launch::Path(TRUE_BIN.into()),
        target: ExecTarget::Path(TRUE_BIN.into()),
        filename: TRUE_BIN.into(),
        expect_ino: m.ino(),
        expect_dev: stat_dev_to_kernel_dev(m.dev()),
        deleted: false,
        tmpfs: false,
    });
    match &fx.shm {
        Ok((_, copy)) => {
            let m = fs::symlink_metadata(copy)?;
            let name = copy.to_string_lossy().into_owned();
            cases.push(ExecCase {
                label: "a copy in /dev/shm",
                launch: Launch::Path(name.clone()),
                target: ExecTarget::Path(copy.clone()),
                filename: name,
                expect_ino: m.ino(),
                expect_dev: stat_dev_to_kernel_dev(m.dev()),
                deleted: false,
                tmpfs: true,
            });
        }
        Err(e) => rep.check(
            "exec of a copy in /dev/shm",
            false,
            false,
            format!("copy not created: {e}"),
        ),
    }
    let m = fx.deleted.metadata()?;
    let path = format!("/proc/{me}/fd/{}", fx.deleted.as_raw_fd());
    cases.push(ExecCase {
        label: "a deleted file (through /proc/<pid>/fd)",
        launch: Launch::Path(path.clone()),
        target: ExecTarget::File(&fx.deleted),
        filename: path,
        expect_ino: m.ino(),
        expect_dev: stat_dev_to_kernel_dev(m.dev()),
        deleted: true,
        tmpfs: false,
    });
    match &fx.memfd {
        Some(memfd) => {
            let m = memfd.metadata()?;
            let fd = memfd.as_raw_fd();
            let path = format!("/proc/{me}/fd/{fd}");
            cases.push(ExecCase {
                label: "a memfd (through /proc/<pid>/fd)",
                launch: Launch::Path(path.clone()),
                target: ExecTarget::File(memfd),
                filename: path,
                expect_ino: m.ino(),
                expect_dev: stat_dev_to_kernel_dev(m.dev()),
                deleted: true,
                tmpfs: true,
            });
            cases.push(ExecCase {
                label: "a memfd with execveat(fd, \"\", AT_EMPTY_PATH) (fexecve)",
                launch: Launch::Execveat(fd),
                target: ExecTarget::File(memfd),
                filename: format!("/dev/fd/{fd}"),
                expect_ino: m.ino(),
                expect_dev: stat_dev_to_kernel_dev(m.dev()),
                deleted: true,
                tmpfs: true,
            });
        }
        None => rep.check(
            "exec of a memfd",
            false,
            false,
            format!("memfd not created: {}", fx.memfd_note),
        ),
    }

    for c in &cases {
        p.begin();
        let vetted = vet_exec_target(&c.target, ROOT_UID, if c.deleted { 0 } else { 1 });
        let started = match (&c.launch, vetted) {
            (_, Err(why)) => Err(std::io::Error::other(format!("refused: {why}"))),
            (Launch::Path(path), Ok(())) => Command::new(path).spawn().and_then(|mut child| {
                let pid = child.id();
                child.wait().map(|st| (pid, st.success()))
            }),
            (Launch::Execveat(fd), Ok(())) => fexecve_child(*fd),
        };
        let evs = p.drain();
        let (child, status) = match &started {
            Ok((pid, true)) => (*pid, "ran".to_string()),
            Ok((pid, false)) => (*pid, "exited non-zero".to_string()),
            Err(e) => (0, format!("not executed: {e}")),
        };
        let ev = evs.iter().find(|e| e.kind == PROBE_KIND_EXEC);
        let (ok, evidence) = match ev {
            None => (
                false,
                format!("{status}; no exec record ({} other)", evs.len()),
            ),
            Some(e) => {
                let filename = String::from_utf8_lossy(detail(e)).into_owned();
                let nlink_ok = if c.deleted {
                    e.nlink == 0
                } else {
                    e.nlink >= 1
                };
                let magic_ok = if c.tmpfs {
                    e.s_magic == TMPFS_MAGIC
                } else {
                    e.s_magic != 0 && e.s_magic != TMPFS_MAGIC
                };
                let ok = filename == c.filename
                    && e.ino == c.expect_ino
                    && e.dev == c.expect_dev
                    && e.mode & S_IFMT == S_IFREG
                    && nlink_ok
                    && magic_ok
                    && e.pid == child
                    && child != me;
                (
                    ok,
                    format!(
                        "{status}; filename {filename}, ino {} (expected {}), nlink {}, i_mode {:o}, s_magic {:#x}, path {}",
                        e.ino,
                        c.expect_ino,
                        e.nlink,
                        e.mode,
                        e.s_magic,
                        rendered_path(e)
                    ),
                )
            }
        };
        rep.check(
            format!(
                "exec of {}: filename, inode, link count and filesystem magic",
                c.label
            ),
            true,
            ok,
            evidence,
        );
    }
    Ok(())
}

/// `fork` + `execveat(fd, "", AT_EMPTY_PATH)`: the child's pid and whether
/// it exited 0. The child only makes the two syscalls (async-signal-safe
/// after a fork from a multi-threaded process).
fn fexecve_child(fd: i32) -> std::io::Result<(u32, bool)> {
    let empty = CString::new("").map_err(std::io::Error::other)?;
    let arg0 = CString::new("true").map_err(std::io::Error::other)?;
    let argv = [arg0.as_ptr(), std::ptr::null()];
    let envp = [std::ptr::null::<libc::c_char>()];
    match unsafe { libc::fork() } {
        -1 => Err(std::io::Error::last_os_error()),
        0 => unsafe {
            libc::syscall(
                libc::SYS_execveat,
                fd,
                empty.as_ptr(),
                argv.as_ptr(),
                envp.as_ptr(),
                libc::AT_EMPTY_PATH,
            );
            libc::_exit(127)
        },
        pid => {
            let mut status = 0;
            if unsafe { libc::waitpid(pid, &mut status, 0) } < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok((
                pid as u32,
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
            ))
        }
    }
}

fn exercise_dns(
    p: &mut Probes,
    rep: &mut Report,
    ret4: &[String],
    ret6: &[String],
    send: &[String],
) -> Result<()> {
    let packet = dns_query_packet(DNS_NAME);
    let carries = |e: &SensorProbeRaw| {
        detail(e).len() >= packet.len() && detail(e)[..packet.len()] == packet[..] && e.aux != 0
    };
    for (family, bind, to, ret_kind, ret_attached, send_sym) in [
        (
            "IPv4",
            "127.0.0.1:0",
            "127.0.0.1:53",
            PROBE_KIND_DNS4,
            !ret4.is_empty(),
            "udp_send_skb",
        ),
        (
            "IPv6",
            "[::1]:0",
            "[::1]:53",
            PROBE_KIND_DNS6,
            !ret6.is_empty(),
            "udp_v6_send_skb",
        ),
    ] {
        p.begin();
        let sent = UdpSocket::bind(bind).and_then(|s| s.send_to(&packet, to));
        let evs = p.drain();
        if let Err(e) = sent {
            rep.check(
                format!("{family} DNS query: payload read after the copy"),
                family == "IPv4",
                false,
                format!("query not sent: {e}"),
            );
            continue;
        }
        let via_ret = evs.iter().any(|e| e.kind == ret_kind && carries(e));
        let send_attached = send.iter().any(|s| s.starts_with(send_sym));
        let via_send = evs
            .iter()
            .any(|e| e.kind == PROBE_KIND_UDP_SEND_SKB && carries(e));
        let ret_fn = if family == "IPv4" {
            "ip_make_skb"
        } else {
            "ip6_make_skb"
        };
        rep.check(
            format!(
                "{family} DNS query: kretprobe {ret_fn} reads the QNAME from the socket buffer"
            ),
            false,
            via_ret,
            format!("attached: {ret_attached}; records: {}", kinds(&evs)),
        );
        rep.check(
            format!("{family} DNS query: kprobe {send_sym} reads the QNAME from the socket buffer"),
            false,
            via_send,
            format!("attached: {send_attached}; records: {}", kinds(&evs)),
        );
        rep.check(
            format!("{family} DNS query: at least one candidate reads the QNAME after the kernel copied it"),
            true,
            via_ret || via_send,
            format!("{} byte query to {to}", packet.len()),
        );
    }
    Ok(())
}

/// `NN_FEASIBILITY_BENCH=<opens>`: measure the cost per open (step 1
/// sizing). Off by default.
fn bench_opens_requested() -> Option<u32> {
    std::env::var("NN_FEASIBILITY_BENCH")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|n| *n >= 1000)
}

/// Median open+close rate over 5 rounds of `n / 5`, read-only and
/// write-only (no write, no truncation: the open path only).
fn bench_rates(path: &Path, n: u32) -> (f64, f64) {
    let Ok(c) = CString::new(path.as_os_str().as_encoded_bytes()) else {
        return (0.0, 0.0);
    };
    let rate = |flags: libc::c_int| {
        let per = n / 5;
        let mut rounds: Vec<f64> = (0..5)
            .map(|_| {
                let start = Instant::now();
                for _ in 0..per {
                    let fd = unsafe { libc::open(c.as_ptr(), flags) };
                    if fd >= 0 {
                        unsafe { libc::close(fd) };
                    }
                }
                f64::from(per) / start.elapsed().as_secs_f64()
            })
            .collect();
        rounds.sort_by(f64::total_cmp);
        rounds[2]
    };
    (
        rate(libc::O_RDONLY | libc::O_CLOEXEC),
        rate(libc::O_WRONLY | libc::O_CLOEXEC),
    )
}

fn p_bench(rep: &mut Report, phase: &str, path: &Path, n: u32) {
    let (read, write) = bench_rates(path, n);
    rep.bench.push((phase.to_string(), read, write));
}

// ───────────────────────────── report ─────────────────────────────

struct ProgRow {
    program: &'static str,
    point: String,
    verifier: String,
    insns: String,
    xlated: String,
    attached: String,
}

struct Check {
    property: String,
    required: bool,
    pass: bool,
    evidence: String,
}

#[derive(Default)]
struct Report {
    kernel: String,
    notes: Vec<String>,
    programs: Vec<ProgRow>,
    offsets: Vec<(String, String)>,
    checks: Vec<Check>,
    /// (program, tail of the verifier output) for rejected programs.
    logs: Vec<(&'static str, String)>,
    /// `NN_FEASIBILITY_BENCH`: (phase, read-only opens/s, write opens/s).
    bench: Vec<(String, f64, f64)>,
}

impl Report {
    fn check(
        &mut self,
        property: impl Into<String>,
        required: bool,
        pass: bool,
        evidence: impl Into<String>,
    ) {
        self.checks.push(Check {
            property: property.into(),
            required,
            pass,
            evidence: evidence.into(),
        });
    }

    fn missing(&mut self, program: &'static str, point: String) -> bool {
        self.programs.push(ProgRow {
            program,
            point,
            verifier: "not in the object".into(),
            insns: "—".into(),
            xlated: "—".into(),
            attached: "—".into(),
        });
        false
    }

    fn rejected(&mut self, program: &'static str, point: String, e: &ProgramError) -> bool {
        let source = std::error::Error::source(e).map_or_else(String::new, |s| format!(" ({s})"));
        self.programs.push(ProgRow {
            program,
            point,
            verifier: format!("REJECTED{source}"),
            insns: "—".into(),
            xlated: "—".into(),
            attached: "—".into(),
        });
        let text = e.to_string();
        let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        self.logs
            .push((program, lines[lines.len().saturating_sub(8)..].join("\n")));
        false
    }

    fn loaded(
        &mut self,
        program: &'static str,
        point: String,
        info: Result<ProgramInfo, ProgramError>,
        attached: Result<String, String>,
    ) -> bool {
        let (insns, xlated) = match &info {
            Ok(i) => (
                i.verified_instruction_count()
                    .map_or_else(|| "n/a".to_string(), |n| n.to_string()),
                i.size_translated()
                    .map_or_else(|| "n/a".to_string(), |n| n.to_string()),
            ),
            Err(_) => ("n/a".to_string(), "n/a".to_string()),
        };
        let ok = attached.is_ok();
        self.programs.push(ProgRow {
            program,
            point,
            verifier: "accepted".into(),
            insns,
            xlated,
            attached: match attached {
                Ok(s) => s,
                Err(e) => format!("NO — {e}"),
            },
        });
        ok
    }

    fn passed(&self) -> bool {
        self.checks.iter().all(|c| !c.required || c.pass)
    }

    fn print(&self) {
        println!(
            "# Tappa 10.9 step 0 — sensor feasibility on {}\n",
            self.kernel
        );
        for n in &self.notes {
            println!("- {n}");
        }
        println!("\n## Programs\n");
        println!(
            "| program | attach point | verifier | verified insns | xlated bytes | attached |"
        );
        println!("|---|---|---|---|---|---|");
        for p in &self.programs {
            println!(
                "| `{}` | {} | {} | {} | {} | {} |",
                p.program,
                p.point,
                p.verifier,
                p.insns,
                p.xlated,
                p.attached.replace('|', "/")
            );
        }
        println!("\n## New offsets (live BTF)\n");
        println!("| field | byte offset |");
        println!("|---|---|");
        for (f, o) in &self.offsets {
            println!("| `{f}` | {o} |");
        }
        println!("\n## Properties\n");
        println!("| result | property | evidence |");
        println!("|---|---|---|");
        for c in &self.checks {
            let result = match (c.pass, c.required) {
                (true, _) => "PASS",
                (false, true) => "**FAIL**",
                (false, false) => "no (info)",
            };
            println!(
                "| {result} | {} | {} |",
                c.property,
                c.evidence.replace('|', "/")
            );
        }
        if let Some((_, base_r, base_w)) = self.bench.iter().find(|(p, _, _)| p == "no program") {
            println!("\n## Cost per open (NN_FEASIBILITY_BENCH)\n");
            println!(
                "| phase | read-only opens/s | added per open | write opens/s | added per open |"
            );
            println!("|---|---|---|---|---|");
            let added = |rate: f64, base: f64| {
                if rate > 0.0 && base > 0.0 {
                    format!(
                        "{:+.0} ns ({:+.1} %)",
                        (1.0 / rate - 1.0 / base) * 1e9,
                        (base - rate) / base * -100.0
                    )
                } else {
                    "n/a".to_string()
                }
            };
            for (phase, r, w) in self.bench.iter().rev() {
                println!(
                    "| {phase} | {r:.0} | {} | {w:.0} | {} |",
                    added(*r, *base_r),
                    added(*w, *base_w)
                );
            }
        }
        for (program, log) in &self.logs {
            println!("\n### Verifier output, `{program}` (last lines)\n\n```\n{log}\n```");
        }
        let required: Vec<&Check> = self.checks.iter().filter(|c| c.required).collect();
        let ok = required.iter().filter(|c| c.pass).count();
        println!(
            "\nRESULT: {} — {ok}/{} required properties hold",
            if self.passed() { "PASS" } else { "FAIL" },
            required.len()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn euid() -> u32 {
        unsafe { libc::geteuid() }
    }

    /// External audit SNS-003: the runner used fixed names in world-writable
    /// directories (`<base>/nn-feasibility`, `/dev/shm/nn-feasibility-true`),
    /// removed and re-created them as root, then executed the copy.
    #[test]
    fn fixtures_are_private_and_fresh() {
        let base = tempfile::tempdir().unwrap();
        let shm_base = tempfile::tempdir().unwrap();
        // The old fixed names, pre-created by someone else.
        let old_work = base.path().join("nn-feasibility");
        fs::create_dir(&old_work).unwrap();
        fs::write(old_work.join("plain"), b"planted").unwrap();
        let old_shm = shm_base.path().join("nn-feasibility-true");
        fs::write(&old_shm, b"planted").unwrap();

        let a = PrivateDir::create(base.path(), WORK_PREFIX).unwrap();
        let b = PrivateDir::create(base.path(), WORK_PREFIX).unwrap();
        assert_ne!(a.path(), b.path(), "every run gets a fresh directory");
        for d in [&a, &b] {
            assert_eq!(d.path().parent(), Some(base.path()));
            assert_ne!(d.path(), old_work.as_path());
            let m = fs::symlink_metadata(d.path()).unwrap();
            assert!(m.is_dir());
            assert_eq!(m.uid(), euid());
            assert_eq!(m.mode() & 0o077, 0, "no access for group or others");
        }

        let fx = Fixtures::create(a.path(), shm_base.path()).unwrap();
        let plain = fs::symlink_metadata(fx.path("plain")).unwrap();
        assert!(plain.is_file());
        assert_eq!(plain.mode() & 0o077, 0);
        let (shm_dir, copy) = fx.shm.as_ref().expect("tmpfs copy created");
        assert_eq!(shm_dir.path().parent(), Some(shm_base.path()));
        assert_ne!(copy.as_path(), old_shm.as_path());
        let m = fs::symlink_metadata(shm_dir.path()).unwrap();
        assert_eq!(m.mode() & 0o077, 0);
        // What exercise_exec checks before each exec (owner: this user).
        assert_eq!(
            vet_exec_target(&ExecTarget::Path(copy.clone()), euid(), 1),
            Ok(())
        );
        assert_eq!(
            vet_exec_target(&ExecTarget::File(&fx.deleted), euid(), 0),
            Ok(())
        );

        // The old names are left alone, before and after the cleanup.
        let (work, shm) = (a.path().to_path_buf(), shm_dir.path().to_path_buf());
        drop(fx);
        drop(a);
        assert!(!work.exists() && !shm.exists(), "own directories removed");
        assert!(b.path().is_dir(), "another run's directory kept");
        assert_eq!(fs::read(old_work.join("plain")).unwrap(), b"planted");
        assert_eq!(fs::read(&old_shm).unwrap(), b"planted");
    }

    #[test]
    fn fixture_files_are_never_reused_or_followed() {
        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().join("existing");
        fs::write(&existing, b"keep").unwrap();
        assert!(create_private(&existing, 0o600).is_err());
        let link = dir.path().join("link");
        symlink(&existing, &link).unwrap();
        assert!(create_private(&link, 0o600).is_err());
        assert!(copy_true(&link).is_err());
        assert_eq!(fs::read(&existing).unwrap(), b"keep");
    }

    #[test]
    fn exec_target_is_vetted_before_exec() {
        let dir = tempfile::tempdir().unwrap();
        let own = |name: &str| {
            let p = dir.path().join(name);
            create_private(&p, 0o700).unwrap();
            p
        };
        let ok = own("ok");
        assert_eq!(
            vet_exec_target(&ExecTarget::Path(ok.clone()), euid(), 1),
            Ok(())
        );
        // Another owner.
        assert!(vet_exec_target(&ExecTarget::Path(ok.clone()), euid() + 1, 1).is_err());
        // A symlink to a good file.
        let link = dir.path().join("link");
        symlink(&ok, &link).unwrap();
        assert!(vet_exec_target(&ExecTarget::Path(link), euid(), 1).is_err());
        // A second name for the file.
        let linked = own("linked");
        fs::hard_link(&linked, dir.path().join("second-name")).unwrap();
        assert!(vet_exec_target(&ExecTarget::Path(linked), euid(), 1).is_err());
        // Writable by the group.
        let shared = own("shared");
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(vet_exec_target(&ExecTarget::Path(shared), euid(), 1).is_err());
        // Not a regular file.
        let sub = dir.path().join("sub");
        fs::create_dir(&sub).unwrap();
        assert!(vet_exec_target(&ExecTarget::Path(sub), euid(), 1).is_err());
    }
}
