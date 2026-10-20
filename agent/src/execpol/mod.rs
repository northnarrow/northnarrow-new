//! Lab PR 226 (EXPERIMENTAL) — synchronous exec policies (CM-01) and the
//! exec environment / executable mapping checks (CM-25), the agent half.
//! Design: `docs/design/EXEC_POLICY.md`; kernel half:
//! `agent-ebpf/src/execpol.rs`; wire: `common::wire::execpol`.
//!
//! The kernel refuses an exec (`-EACCES` from `bprm_check_security`, before
//! the exec's point of no return) when the signed policy says so for the
//! file's class (memfd, deleted file, `/dev/shm`, `/tmp`, `/var/tmp`, a
//! world-writable directory, a home, another user's home, a guarded
//! mount) and the caller's lineage tier (interactive admin session, login
//! session, system service, unknown); hands the exec to the exec
//! quarantine (lab PR 223) for a quarantine cell; records a "would deny"
//! for an audit cell or a class in audit mode. At exec it also judges a
//! bounded prefix of the new environment (`LD_PRELOAD`, `LD_AUDIT` into a
//! staging path; `GLIBC_TUNABLES` at a set-id target; history tricks), and
//! on `mmap_file` the executable mappings of files in a class. This module
//! writes the policy into the kernel (frozen), keeps the slices and images
//! current and turns the kernel's reports into signed records.
//!
//! Off unless `--exec-policy audit|enforce`; a detect-only agent audits.
//! Fail-open: the programs detach with the agent.

pub mod controller;
pub mod kernel;
pub mod policy;
pub mod record;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{LazyLock, OnceLock};

use anyhow::{anyhow, Context, Result};
use aya::programs::{Lsm, TracePoint};
use aya::{Btf, Ebpf};
use common::wire::execpol::{counter, mode};
use parking_lot::Mutex;
use tracing::{info, warn};

pub use policy::{Profile, Table};

/// Exec refused (or "would deny") by the policy.
pub const RULE_EXEC: &str = "NN-L-EXECPOL-001_StagingExecDenied";
pub const RULE_EXEC_NAME: &str = "Exec from a staging location refused by the exec policy";
/// A loader variable (`LD_PRELOAD`, `LD_AUDIT`) naming a staging path.
pub const RULE_PRELOAD: &str = "NN-L-EXECENV-001_PreloadFromStaging";
pub const RULE_PRELOAD_NAME: &str = "Loader variable naming a staging path at exec";
/// `GLIBC_TUNABLES` at a set-id target, history disabled, a library path
/// into staging.
pub const RULE_ENV: &str = "NN-L-EXECENV-002_ExecEnvironmentTrick";
pub const RULE_ENV_NAME: &str = "Exec environment trick";
/// An executable mapping of a file in a staging class.
pub const RULE_MAP: &str = "NN-L-EXECENV-003_ExecMappingFromStaging";
pub const RULE_MAP_NAME: &str = "Executable mapping of a file from a staging location";
/// The records' `detection_type`.
pub const CATEGORY: &str = "malware_prevention";
/// The signed overlay (`nn-admin config overlay set exec-policy`).
pub const DEFAULT_POLICY_LOCAL: &str = "/etc/northnarrow/exec-policy.local";

/// The kernel programs.
pub const ENV_EXECVE_PROGRAM: &str = "execpol_env_execve";
pub const ENV_EXECVEAT_PROGRAM: &str = "execpol_env_execveat";
pub const MAP_PROGRAM: &str = "execmap_check";

/// `--exec-policy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Mode {
    /// Nothing classified for the policy, nothing denied (the default).
    Off,
    /// Every deny recorded as "would deny", the exec runs; quarantine cells
    /// still hand execs to the exec quarantine.
    Audit,
    /// Deny cells refuse the exec.
    Enforce,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Audit => "audit",
            Mode::Enforce => "enforce",
        }
    }

    fn kernel(self) -> u64 {
        match self {
            Mode::Off => mode::OFF,
            Mode::Audit => mode::AUDIT,
            Mode::Enforce => mode::ENFORCE,
        }
    }
}

/// The policy's configuration for this boot.
#[derive(Debug, Clone)]
pub struct Config {
    pub mode: Mode,
    pub table: Table,
    /// Where the table came from (`server profile (built in)`, the signed
    /// overlay's path).
    pub source: String,
    /// The loader-variable checks (`--exec-policy-env`).
    pub env: bool,
    /// The executable-mapping checks (`--exec-policy-map`).
    pub map: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            mode: Mode::Off,
            table: Table::builtin(Profile::Server),
            source: "server profile (built in)".into(),
            env: true,
            map: true,
        }
    }
}

static CONFIG: OnceLock<Config> = OnceLock::new();
static KERNEL: Mutex<Option<kernel::Kernel>> = Mutex::new(None);
static STATE: Mutex<Option<String>> = Mutex::new(None);
/// What runs partly: each a signed `subsystem_degraded` at start.
static NOTES: Mutex<Vec<String>> = Mutex::new(Vec::new());
static STOPPING: AtomicBool = AtomicBool::new(false);

pub fn configure(cfg: Config) {
    let _ = CONFIG.set(cfg);
}

pub fn config() -> Option<&'static Config> {
    CONFIG.get()
}

fn set_state(s: impl Into<String>) {
    *STATE.lock() = Some(s.into());
}

/// `off`, `audit`, `enforce`, with what runs partly after `;`, or
/// `degraded: <why>`.
pub fn state() -> String {
    STATE
        .lock()
        .clone()
        .unwrap_or_else(|| Mode::Off.as_str().to_string())
}

/// The partial degradations of this boot, for the signed entries.
pub fn degradations() -> Vec<String> {
    NOTES.lock().clone()
}

fn note(why: String) {
    warn!(reason = %why, "exec policy: degraded");
    NOTES.lock().push(why);
}

/// Whether the optional offsets of `slots` resolved on this kernel.
fn offsets_resolved(slots: &[u32]) -> bool {
    use common::btf_offsets::BTF_OFFSETS_ABSENT;
    let Some(r) = crate::anti_tamper::btf_revalidate::resolved() else {
        return true; // unarmed: the compiled values apply
    };
    slots.iter().all(|s| {
        r.values
            .iter()
            .any(|(k, v)| k == s && *v != BTF_OFFSETS_ABSENT)
    })
}

fn attach_tracepoint(ebpf: &mut Ebpf, program: &str, event: &str) -> Result<()> {
    let prog: &mut TracePoint = ebpf
        .program_mut(program)
        .ok_or_else(|| anyhow!("program {program} missing from the eBPF object"))?
        .try_into()
        .with_context(|| format!("program {program} is not a tracepoint"))?;
    prog.load()
        .with_context(|| format!("verifier rejected `{program}`"))?;
    prog.attach("syscalls", event)
        .with_context(|| format!("attaching tracepoint syscalls/{event}"))?;
    Ok(())
}

fn attach_map_lsm(ebpf: &mut Ebpf) -> Result<()> {
    let btf = Btf::from_sys_fs().context("loading vmlinux BTF for the mapping check")?;
    let prog: &mut Lsm = ebpf
        .program_mut(MAP_PROGRAM)
        .ok_or_else(|| anyhow!("program {MAP_PROGRAM} missing from the eBPF object"))?
        .try_into()
        .with_context(|| format!("program {MAP_PROGRAM} is not LSM"))?;
    prog.load("mmap_file", &btf)
        .with_context(|| format!("verifier rejected `{MAP_PROGRAM}`"))?;
    prog.attach()
        .with_context(|| format!("attaching `{MAP_PROGRAM}`"))?;
    Ok(())
}

/// From the multiplexer, once the exec sensor's mode is known and the exec
/// quarantine's configuration is written: attach the environment and
/// mapping programs the policy needs, write the kernel configuration
/// (always, `OFF` included, then frozen), take the maps. `execq_on`: the
/// exec quarantine runs (it refreshes the guarded mount roots then).
pub fn install(ebpf: &mut Ebpf, execq_on: bool) -> Result<()> {
    let cfg = CONFIG.get().cloned().unwrap_or_default();
    let mut m = cfg.mode;
    if m != Mode::Off && !crate::sensors::exe_identity::lsm_active() {
        set_state(
            "degraded: the exec sensor is not on LSM bprm_check_security (tracepoint mode or \
             refused): no exec can be refused or judged",
        );
        m = Mode::Off;
    }
    let mut env_ok = false;
    let mut map_ok = false;
    if m != Mode::Off {
        if cfg.env && cfg.table.has_env_rules() {
            match attach_tracepoint(ebpf, ENV_EXECVE_PROGRAM, "sys_enter_execve")
                .and_then(|()| attach_tracepoint(ebpf, ENV_EXECVEAT_PROGRAM, "sys_enter_execveat"))
            {
                Ok(()) => env_ok = true,
                Err(e) => note(format!(
                    "exec policy: the environment programs are not attached ({}): LD_PRELOAD, \
                     LD_AUDIT, GLIBC_TUNABLES and the history tricks are not judged at exec",
                    crate::sensors::exe_identity::verifier_tail(&e)
                )),
            }
        }
        if cfg.map && cfg.table.has_map_rules() {
            match attach_map_lsm(ebpf) {
                Ok(()) => map_ok = true,
                Err(e) => note(format!(
                    "exec policy: the mapping check is not attached ({}): executable mappings \
                     of staging files are neither refused nor recorded",
                    crate::sensors::exe_identity::verifier_tail(&e)
                )),
            }
        }
    }
    let words = cfg.table.encode(m.kernel(), env_ok, map_ok, m != Mode::Off);
    kernel::write_conf(ebpf, &words)?;
    if m == Mode::Off {
        if STATE.lock().is_none() {
            set_state(Mode::Off.as_str());
        }
        return Ok(());
    }
    *KERNEL.lock() = Some(kernel::take(ebpf, !execq_on)?);
    use common::btf_offsets::slot;
    if !offsets_resolved(&[
        slot::TASK_STRUCT_SIGNAL_OFFSET,
        slot::SIGNAL_STRUCT_TTY_OFFSET,
    ]) {
        note(
            "exec policy: task_struct.signal / signal_struct.tty not resolved on this kernel: \
             no caller is an interactive admin session (the session rules apply to admins)"
                .into(),
        );
    }
    if !offsets_resolved(&[slot::TASK_STRUCT_LOGINUID_OFFSET]) {
        note(
            "exec policy: task_struct.loginuid not resolved (no CONFIG_AUDIT?): a login \
             session is `unknown`"
                .into(),
        );
    }
    if !offsets_resolved(&[slot::INODE_I_UID_OFFSET]) {
        note("exec policy: inode.i_uid not resolved: no file is in another user's home".into());
    }
    if cfg.table.has_quarantine() && !execq_on {
        note(
            "exec policy: the policy has quarantine cells and the exec quarantine is off \
             (--exec-quarantine): those execs run, counted as `quarantine inactive`"
                .into(),
        );
    }
    let partial = if NOTES.lock().is_empty() {
        String::new()
    } else {
        format!("; {} partial", NOTES.lock().len())
    };
    set_state(format!("{} (starting){partial}", m.as_str()));
    info!(
        mode = m.as_str(),
        profile = cfg.table.profile.as_str(),
        policy = %cfg.source,
        env = env_ok,
        map = map_ok,
        "exec policy armed in the kernel (EXPERIMENTAL, lab PR 226)"
    );
    Ok(())
}

/// The policy cannot run: `degraded: <why>`.
pub fn fail(why: String) {
    *KERNEL.lock() = None;
    set_state(format!("degraded: {why}"));
}

// ── counters ────────────────────────────────────────────────────────

/// What the policy did since boot (`nn-admin status`, appended fields).
#[derive(Debug, Default)]
pub struct Counters {
    pub denied: AtomicU64,
    pub would_deny: AtomicU64,
    pub quarantine: AtomicU64,
    pub quarantine_inactive: AtomicU64,
    pub env_denied: AtomicU64,
    pub env_recorded: AtomicU64,
    pub map_denied: AtomicU64,
    pub map_recorded: AtomicU64,
    pub exempted: AtomicU64,
    /// Records written (after the repeat window and before the per-rule
    /// budget).
    pub records: AtomicU64,
}

impl Counters {
    /// The kernel's per-CPU sums.
    pub fn store_kernel(&self, c: &[u64; counter::SLOTS as usize]) {
        let s = |a: &AtomicU64, slot: u32| a.store(c[slot as usize], Ordering::Relaxed);
        s(&self.denied, counter::DENIED);
        s(&self.would_deny, counter::WOULD_DENY);
        s(&self.quarantine, counter::QUARANTINE);
        s(&self.quarantine_inactive, counter::QUARANTINE_INACTIVE);
        s(&self.env_denied, counter::ENV_DENIED);
        s(&self.env_recorded, counter::ENV_RECORDED);
        s(&self.map_denied, counter::MAP_DENIED);
        s(&self.map_recorded, counter::MAP_RECORDED);
        s(&self.exempted, counter::EXEMPTED);
    }
}

pub static COUNTERS: LazyLock<Counters> = LazyLock::new(Counters::default);

/// A snapshot for the status reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub state: String,
    pub denied: u64,
    pub would_deny: u64,
    pub quarantine: u64,
    pub quarantine_inactive: u64,
    pub env_denied: u64,
    pub env_recorded: u64,
    pub map_denied: u64,
    pub map_recorded: u64,
}

pub fn snapshot() -> Snapshot {
    let c = &*COUNTERS;
    let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
    Snapshot {
        state: state(),
        denied: g(&c.denied),
        would_deny: g(&c.would_deny),
        quarantine: g(&c.quarantine),
        quarantine_inactive: g(&c.quarantine_inactive),
        env_denied: g(&c.env_denied),
        env_recorded: g(&c.env_recorded),
        map_denied: g(&c.map_denied),
        map_recorded: g(&c.map_recorded),
    }
}

// ── start and stop ──────────────────────────────────────────────────

/// The running controller.
pub struct Handle {
    thread: std::thread::JoinHandle<()>,
}

/// Start the controller thread (the slices and images are published
/// before it returns). `Err`: the policy's kernel objects are not there —
/// the kernel then judges with no slices (every caller `unknown`) and no
/// image roles, and nothing is recorded; the reason is for the signed
/// `subsystem_degraded`.
pub fn start(recorder: Box<dyn record::Recorder>, execq_on: bool) -> Result<Handle, String> {
    let cfg = CONFIG.get().cloned().unwrap_or_default();
    let Some(k) = KERNEL.lock().take() else {
        return Err(match STATE.lock().clone() {
            Some(s) if s.starts_with("degraded") => s,
            _ => "the policy's kernel objects were not installed".to_string(),
        });
    };
    let mut ctl = controller::Controller::new(
        k,
        recorder,
        controller::Settings::for_host(cfg.table.exempt.clone(), cfg.source.clone(), !execq_on),
    );
    let (system, user) = ctl.refresh(std::time::Instant::now());
    if system == 0 && user == 0 {
        note(
            "exec policy: no systemd slice found on a cgroup v2 mount: every caller is \
             `unknown` (the strictest column)"
                .into(),
        );
    }
    let partial = if NOTES.lock().is_empty() {
        String::new()
    } else {
        format!("; {} partial", NOTES.lock().len())
    };
    set_state(format!("{}{partial}", cfg.mode.as_str()));
    let thread = std::thread::Builder::new()
        .name("nn-execpol".into())
        .spawn(move || ctl.run(&STOPPING))
        .map_err(|e| format!("controller thread: {e}"))?;
    Ok(Handle { thread })
}

/// Stop the controller (the kernel keeps deciding until the programs
/// detach with the agent).
pub fn shutdown(handle: Option<Handle>) {
    STOPPING.store(true, Ordering::Relaxed);
    if let Some(h) = handle {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while !h.thread.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if h.thread.is_finished() {
            let _ = h.thread.join();
        }
    }
}

/// The policy for this boot: the signed overlay's text over `profile`, or
/// `profile`'s built-in table. `Err`: the overlay does not parse (the
/// overlay gate refuses such a file before it gets here).
pub fn table_from(text: Option<&str>, profile: Profile) -> Result<Table, String> {
    match text {
        Some(t) => policy::parse(t, profile),
        None => Ok(Table::builtin(profile)),
    }
}

/// The table the agent applies at boot ([`boot_table`]).
#[derive(Debug)]
pub struct BootTable {
    pub table: Table,
    /// Where it came from (status surface).
    pub source: String,
    /// A verified file that does not parse — a bad line `overlay set`
    /// refuses: the built-in profile applies instead, and this is the
    /// signed degradation's detail.
    pub degraded: Option<String>,
}

/// The table in force at boot: the verified overlay `(path, text)` over
/// `profile`, or the built-in profile when there is none or it does not
/// parse (then [`BootTable::degraded`] says why).
pub fn boot_table(signed: Option<(&Path, &str)>, profile: Profile) -> BootTable {
    let builtin = |source: String, degraded: Option<String>| BootTable {
        table: Table::builtin(profile),
        source,
        degraded,
    };
    let Some((path, text)) = signed else {
        return builtin(format!("{} profile (built in)", profile.as_str()), None);
    };
    match table_from(Some(text), profile) {
        Ok(table) => BootTable {
            source: format!(
                "{} (signed, over the {} profile)",
                path.display(),
                table.profile.as_str()
            ),
            table,
            degraded: None,
        },
        Err(e) => builtin(
            format!(
                "{} profile (built in; {}: {e})",
                profile.as_str(),
                path.display()
            ),
            Some(format!(
                "{}: {e} — the built-in {} profile applies instead",
                path.display(),
                profile.as_str()
            )),
        ),
    }
}

/// The overlay's default path.
pub fn default_policy_local() -> PathBuf {
    PathBuf::from(DEFAULT_POLICY_LOCAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review A.7: a signed file with a bad line found at boot leaves the
    /// built-in profile in force and is a degradation, not only a log line.
    #[test]
    fn a_bad_line_at_boot_is_a_degradation() {
        let path = Path::new("/etc/northnarrow/exec-policy.local");
        let b = boot_table(
            Some((path, "profile server\nexec nowhere * deny\n")),
            Profile::Server,
        );
        assert_eq!(b.table, Table::builtin(Profile::Server));
        let d = b.degraded.expect("a bad line is a degradation");
        assert!(
            d.contains("exec-policy.local") && d.contains("built-in server profile"),
            "{d}"
        );
        assert!(b.source.contains("built in"), "{}", b.source);
        let ok = boot_table(Some((path, "profile desktop\n")), Profile::Server);
        assert!(ok.degraded.is_none());
        assert_eq!(ok.table.profile, Profile::Desktop);
        assert!(ok.source.contains("signed"), "{}", ok.source);
        let none = boot_table(None, Profile::Desktop);
        assert!(none.degraded.is_none());
        assert_eq!(none.table, Table::builtin(Profile::Desktop));
    }

    #[test]
    fn modes_and_defaults() {
        assert_eq!(Mode::Enforce.kernel(), mode::ENFORCE);
        assert_eq!(Mode::Audit.as_str(), "audit");
        let c = Config::default();
        assert_eq!(c.mode, Mode::Off);
        assert_eq!(c.table, Table::builtin(Profile::Server));
        assert!(c.env && c.map);
    }

    #[test]
    fn the_table_comes_from_the_overlay_or_the_profile() {
        assert_eq!(
            table_from(None, Profile::Desktop).unwrap(),
            Table::builtin(Profile::Desktop)
        );
        let t = table_from(Some("exec tmp service deny\n"), Profile::Server).unwrap();
        assert_eq!(
            t.exec[common::wire::execpol::tier::SERVICE as usize][4],
            policy::Cell::Deny
        );
        assert!(table_from(Some("nonsense"), Profile::Server).is_err());
    }

    #[test]
    fn the_counters_follow_the_kernel() {
        let mut k = [0u64; counter::SLOTS as usize];
        k[counter::MAP_RECORDED as usize] = 5;
        k[counter::QUARANTINE_INACTIVE as usize] = 3;
        let c = Counters::default();
        c.store_kernel(&k);
        assert_eq!(c.map_recorded.load(Ordering::Relaxed), 5);
        assert_eq!(c.quarantine_inactive.load(Ordering::Relaxed), 3);
        assert_eq!(c.denied.load(Ordering::Relaxed), 0);
    }
}
