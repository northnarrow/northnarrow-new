//! Lot 324 (plan S1, F5): the exec and file-open sensors' syscall
//! tracepoints, proven on every CPU at the boot.
//!
//! On Ubuntu 26.04's 7.0 a BPF program on a *syscall* tracepoint
//! (`syscalls/sys_enter_*`), attached as aya attaches it — one perf event,
//! on CPU 0 — ran only for the calls made on CPU 0 (lot 322's lab, with the
//! kernel alone). Upstream: the syscall events read the call's user memory
//! before they run anything from 6.19 on (`syscall_get_data` in
//! `perf_syscall_enter`, absent from 6.18); 57918341dd19 (first in 7.2, not
//! in 7.0 or 7.1) runs the BPF programs before that path and before the
//! per-CPU list check; 2c2b322acdcc (7.2, marked for the stable trees)
//! fixes a stale per-CPU list head after a migration in it. Which of them a
//! distribution's kernel carries is not known from its version, so the
//! boot asks the kernel:
//!
//! 1. [`probe`]: a thread of the agent, pinned to each online CPU in turn,
//!    makes the sensor's call once with an empty path (`execve("")`,
//!    `openat(AT_FDCWD, "")`: refused at once with `ENOENT`, nothing
//!    opened or run). The programs mark the CPU in `SYSCALL_TP_SEEN`, in
//!    the row of their own attach point ([`Point`]), for that thread's
//!    calls and emit no record for them.
//! 2. [`decide`]: every online CPU seen, or not; [`Coverage::verdict`]:
//!    proven only when at least [`MIN_CPUS_PROVEN`] CPUs were tested (on
//!    CPU 0 alone, the perf event's own, the test cannot tell an affected
//!    kernel from another: signed "not proven", the tracepoint kept).
//! 3. [`on_every_cpu`]: not every CPU — the sensor's fallback on the raw
//!    `sys_enter` tracepoint (no perf event: it runs on every CPU, for
//!    every call of the host, and keeps the sensor's call by its number) is
//!    attached, muted (`SYSCALL_TP_EMIT`: the tracepoint still records),
//!    and probed in turn, its own marks only; [`choose`] keeps the one
//!    that covers more, and the outcome is signed (`exec_sensor`,
//!    `file_open_sensor`). The switch to the fallback is one map write,
//!    then the tracepoint is retired: no call recorded twice. The syscall
//!    tracepoint stays where it ran on every CPU: it costs nothing to the
//!    host's other calls.
//!
//! The fallbacks read the call's arguments from its registers
//! (`pt_regs.di`, `si`, `dx`) and skip a 32-bit call (`TS_COMPAT`), as the
//! syscall tracepoints do; they are armed only where those offsets resolve
//! from the kernel's BTF (x86-64).

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use aya::Ebpf;
use aya::maps::Array;
use aya::programs::{RawTracePoint, TracePoint};
use common::btf_offsets::{BTF_OFFSETS_ABSENT, slot};
use tracing::{info, warn};

use crate::anti_tamper::bpf_defense::BpfGuard;
use crate::boot::manifest::{AttachPoints, Took};
use crate::sensors::contract::attach as A;

/// The self-test's thread, in the agent's process: the programs know its
/// calls by their `pid_tgid` (`agent-ebpf/src/exec_check.rs`).
pub const PROBE_MAP: &str = "SYSCALL_TP_PROBE";
/// The round last seen per attach point's row and CPU.
pub const SEEN_MAP: &str = "SYSCALL_TP_SEEN";
/// The CPUs the programs can mark (`exec_check.rs`'s `SEEN_CPUS`; a test
/// holds them equal). A CPU at or above it is never seen: the fallback.
pub const SEEN_CPUS: u32 = 1024;
/// The rows of [`SEEN_MAP`]: one per sensor and attach point.
pub const SEEN_ROWS: u32 = 4;
/// Which attach point of each sensor records its calls
/// (`exec_check.rs`'s `SYSCALL_TP_EMIT`).
pub const EMIT_MAP: &str = "SYSCALL_TP_EMIT";
/// The review of #625 (P2-2): the fewest CPUs a test that saw every online
/// CPU must have run on to prove anything. On the affected kernel the
/// tracepoint runs on its perf event's CPU, 0: a test of CPU 0 alone (one
/// online CPU at the boot) sees it whatever the kernel.
pub const MIN_CPUS_PROVEN: usize = 2;
/// The raw tracepoint both fallbacks attach to.
pub const RAW_TRACEPOINT: &str = "sys_enter";
/// The online CPUs, as the kernel lists them.
pub const ONLINE: &str = "/sys/devices/system/cpu/online";
/// How long the probing thread may take, all CPUs included. A CPU it has
/// not reached by then is [`Cpu::Late`].
const PROBE_DEADLINE: Duration = Duration::from_secs(5);

/// The two sensors on a syscall tracepoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sensor {
    /// `exec_check`: `sys_enter_execve` (the exec sensor's tracepoint mode).
    Exec,
    /// `file_open`: `sys_enter_openat` (the LSM file-open sensor's fallback).
    Open,
}

/// A sensor's two attach points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Point {
    /// The syscall tracepoint (`sys_enter_execve`, `sys_enter_openat`).
    Tracepoint,
    /// The raw `sys_enter` fallback.
    Fallback,
}

impl Point {
    /// Its value in `SYSCALL_TP_EMIT` (`exec_check.rs`'s `BY_TRACEPOINT`,
    /// `BY_RAW`).
    pub fn by(self) -> u32 {
        match self {
            Point::Tracepoint => 0,
            Point::Fallback => 1,
        }
    }
}

impl Sensor {
    /// The row of `SYSCALL_TP_SEEN` its program at `point` marks
    /// (`exec_check.rs`'s `SEEN_EXEC_TP`, `SEEN_OPEN_TP`, `SEEN_EXEC_RAW`,
    /// `SEEN_OPEN_RAW`). The review of #625 (P2-1): one per attach point,
    /// so the fallback's test, run with the tracepoint still attached,
    /// never reads the tracepoint's marks.
    pub fn row(self, point: Point) -> u32 {
        match (self, point) {
            (Sensor::Exec, Point::Tracepoint) => 0,
            (Sensor::Open, Point::Tracepoint) => 1,
            (Sensor::Exec, Point::Fallback) => 2,
            (Sensor::Open, Point::Fallback) => 3,
        }
    }

    /// Its slot of `SYSCALL_TP_EMIT` (`EMIT_EXEC`, `EMIT_OPEN`).
    pub fn emit_slot(self) -> u32 {
        match self {
            Sensor::Exec => 0,
            Sensor::Open => 1,
        }
    }

    /// The program on the syscall tracepoint (its name is the event's).
    pub fn tracepoint_program(self) -> &'static str {
        match self {
            Sensor::Exec => "sys_enter_execve",
            Sensor::Open => "sys_enter_openat",
        }
    }

    /// The fallback on the raw `sys_enter` tracepoint.
    pub fn fallback_program(self) -> &'static str {
        match self {
            Sensor::Exec => "exec_check_raw",
            Sensor::Open => "file_open_raw",
        }
    }

    /// The boot manifest's sensor.
    pub fn manifest_sensor(self) -> &'static str {
        match self {
            Sensor::Exec => "exec",
            Sensor::Open => "file_open",
        }
    }

    /// The attach points as the boot notes them (`contract::attach`).
    pub fn tracepoint_note(self) -> &'static str {
        match self {
            Sensor::Exec => A::EXEC_TRACEPOINT,
            Sensor::Open => A::OPEN_TRACEPOINT,
        }
    }

    pub fn fallback_note(self) -> &'static str {
        match self {
            Sensor::Exec => A::EXEC_RAW_TP,
            Sensor::Open => A::OPEN_RAW_TP,
        }
    }

    /// The degradation registry's source.
    pub fn degradation_source(self) -> &'static str {
        match self {
            Sensor::Exec => "exec_sensor",
            Sensor::Open => "file_open_sensor",
        }
    }

    /// The offsets of `pt_regs` its fallback reads, and `thread_info.status`
    /// (a 32-bit call is skipped by it).
    fn fallback_slots(self) -> &'static [(u32, &'static str)] {
        match self {
            Sensor::Exec => &[
                (slot::PT_REGS_DI_OFFSET, "pt_regs.di"),
                (slot::TASK_STRUCT_TI_STATUS_OFFSET, "thread_info.status"),
            ],
            Sensor::Open => &[
                (slot::PT_REGS_SI_OFFSET, "pt_regs.si"),
                (slot::PT_REGS_DX_OFFSET, "pt_regs.dx"),
                (slot::TASK_STRUCT_TI_STATUS_OFFSET, "thread_info.status"),
            ],
        }
    }

    /// The self-test's call, with an empty path: refused with `ENOENT`
    /// before the kernel looks anything up (`getname`), after the syscall
    /// tracepoints and the raw `sys_enter` ran.
    fn call(self) {
        static EMPTY: &[u8; 1] = b"\0";
        let argv: [*const libc::c_char; 1] = [std::ptr::null()];
        // SAFETY: both calls take a NUL-terminated path in our memory, and
        // `execve` a NULL-terminated argv/envp in our memory; neither keeps a
        // pointer past the call. They fail with ENOENT and return.
        let rc = unsafe {
            match self {
                Sensor::Exec => libc::syscall(
                    libc::SYS_execve,
                    EMPTY.as_ptr() as *const libc::c_char,
                    argv.as_ptr(),
                    argv.as_ptr(),
                ),
                Sensor::Open => libc::syscall(
                    libc::SYS_openat,
                    libc::AT_FDCWD,
                    EMPTY.as_ptr() as *const libc::c_char,
                    libc::O_RDONLY | libc::O_CLOEXEC,
                ),
            }
        };
        if rc >= 0 && self == Sensor::Open {
            // never, for an empty path; a descriptor is not left open
            // SAFETY: a descriptor this call opened, closed once.
            unsafe { libc::close(rc as libc::c_int) };
        }
    }
}

/// What the self-test found on one CPU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cpu {
    /// The program ran for the thread's call there.
    Seen,
    /// The thread's call ran there and the program did not.
    Missed,
    /// The thread could not run there (the agent's CPU set leaves it out):
    /// nothing is known of it.
    Unpinned,
    /// The review of #625 (P3-1): the test's deadline passed before the
    /// thread got there (a CPU that never ran it): nothing is known of it.
    Late,
}

/// The self-test's verdict on one attach point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coverage {
    pub seen: Vec<u32>,
    pub missed: Vec<u32>,
    pub unpinned: Vec<u32>,
    pub late: Vec<u32>,
}

/// What a tracepoint's test proves ([`Coverage::verdict`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Every online CPU seen, [`MIN_CPUS_PROVEN`] of them at least.
    Proven,
    /// Every online CPU seen, but fewer than [`MIN_CPUS_PROVEN`]: CPU 0
    /// alone proves nothing of the CPU-0-only kernel.
    NotProven,
    /// A CPU missed, or not tested.
    NotEvery,
}

impl Coverage {
    /// Every online CPU seen (and at least one CPU tested).
    pub fn every(&self) -> bool {
        !self.seen.is_empty()
            && self.missed.is_empty()
            && self.unpinned.is_empty()
            && self.late.is_empty()
    }

    /// [`Verdict::Proven`] when every online CPU was seen and there were
    /// [`MIN_CPUS_PROVEN`] at least.
    pub fn verdict(&self) -> Verdict {
        if !self.every() {
            Verdict::NotEvery
        } else if self.seen.len() < MIN_CPUS_PROVEN {
            Verdict::NotProven
        } else {
            Verdict::Proven
        }
    }

    /// Every CPU `other` saw, this one saw too.
    pub fn covers(&self, other: &Coverage) -> bool {
        let mine: BTreeSet<u32> = self.seen.iter().copied().collect();
        other.seen.iter().all(|c| mine.contains(c))
    }

    /// `CPUs 0-3 seen, 1 and 2 missed, 3 not reachable by the agent`.
    pub fn describe(&self) -> String {
        let mut parts = vec![format!("seen on CPUs {}", cpu_list(&self.seen))];
        if !self.missed.is_empty() {
            parts.push(format!("missed on CPUs {}", cpu_list(&self.missed)));
        }
        if !self.unpinned.is_empty() {
            parts.push(format!(
                "not tested on CPUs {} (the agent cannot run there)",
                cpu_list(&self.unpinned)
            ));
        }
        if !self.late.is_empty() {
            parts.push(format!(
                "not tested on CPUs {} (the self-test's deadline passed first)",
                cpu_list(&self.late)
            ));
        }
        parts.join(", ")
    }
}

/// The self-test's per-CPU results, as a verdict (CPUs in order).
pub fn decide(results: &[(u32, Cpu)]) -> Coverage {
    let mut c = Coverage {
        seen: Vec::new(),
        missed: Vec::new(),
        unpinned: Vec::new(),
        late: Vec::new(),
    };
    let mut sorted = results.to_vec();
    sorted.sort_by_key(|(cpu, _)| *cpu);
    for (cpu, r) in sorted {
        match r {
            Cpu::Seen => c.seen.push(cpu),
            Cpu::Missed => c.missed.push(cpu),
            Cpu::Unpinned => c.unpinned.push(cpu),
            Cpu::Late => c.late.push(cpu),
        }
    }
    c
}

/// Which attach point the sensor keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice {
    /// The syscall tracepoint: proven on every CPU, or its fallback no
    /// better (not attached, or it saw a CPU less).
    Tracepoint,
    /// The raw `sys_enter` fallback: the tracepoint is not proven on every
    /// CPU and the fallback saw every CPU it saw.
    Fallback,
}

/// The tracepoint's verdict and the fallback's (`None`: not attached).
/// Where the agent cannot run on a CPU nothing proves the tracepoint
/// there, and the fallback, which no perf event confines, is taken. A
/// fallback seen on no CPU proves nothing either (the self-test's own
/// calls not recognised, the sensor's switch off): the tracepoint stays.
/// The fallback's verdict is read from its own row ([`Sensor::row`]): the
/// tracepoint, still attached during its test, cannot lend it a CPU.
pub fn choose(tracepoint: &Coverage, fallback: Option<&Coverage>) -> Choice {
    if tracepoint.every() {
        return Choice::Tracepoint;
    }
    match fallback {
        Some(f) if !f.seen.is_empty() && f.covers(tracepoint) => Choice::Fallback,
        _ => Choice::Tracepoint,
    }
}

/// `0-3`, `0,2,5-7`.
pub fn cpu_list(cpus: &[u32]) -> String {
    if cpus.is_empty() {
        return "none".to_string();
    }
    let mut out: Vec<String> = Vec::new();
    let mut i = 0;
    while i < cpus.len() {
        let start = cpus[i];
        let mut end = start;
        while i + 1 < cpus.len() && cpus[i + 1] == end + 1 {
            i += 1;
            end = cpus[i];
        }
        out.push(if start == end {
            start.to_string()
        } else {
            format!("{start}-{end}")
        });
        i += 1;
    }
    out.join(",")
}

/// The kernel's CPU list (`0-3,5`): `None` for anything else.
pub fn parse_cpu_list(text: &str) -> Option<Vec<u32>> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let mut cpus = BTreeSet::new();
    for part in text.split(',') {
        let (a, b) = match part.split_once('-') {
            Some((a, b)) => (a.parse::<u32>().ok()?, b.parse::<u32>().ok()?),
            None => {
                let a = part.parse::<u32>().ok()?;
                (a, a)
            }
        };
        if b < a || b - a > 65_536 {
            return None;
        }
        cpus.extend(a..=b);
    }
    Some(cpus.into_iter().collect())
}

/// The rounds of a sensor's two tests ([`probe`]): each its own, so a mark
/// the tracepoint's test left is never read as the fallback's (the marks
/// start at 0 with the object, and each sensor has its row).
pub const ROUND_TRACEPOINT: u32 = 1;
pub const ROUND_FALLBACK: u32 = 2;

/// The self-test of `sensor`'s program at `point` on `cpus`: one call per
/// CPU from a thread pinned there, then the marks of `round` (non-zero) in
/// that attach point's row read back. The CPUs the thread has not reached
/// by the deadline are [`Cpu::Late`] (the review of #625, P3-1: the
/// partial results are kept), and the thread stops before its next call.
pub fn probe(
    ebpf: &mut Ebpf,
    sensor: Sensor,
    point: Point,
    cpus: &[u32],
    round: u32,
) -> Result<Vec<(u32, Cpu)>> {
    if round == 0 {
        bail!("round 0 is no round: the marks start at 0");
    }
    let (tid_tx, tid_rx) = mpsc::channel::<u64>();
    let (go_tx, go_rx) = mpsc::channel::<()>();
    let (ran_tx, ran_rx) = mpsc::channel::<(u32, bool)>();
    let stop = Arc::new(AtomicBool::new(false));
    let list = cpus.to_vec();
    let halt = Arc::clone(&stop);
    std::thread::Builder::new()
        .name("nn-cpu-selftest".to_string())
        .spawn(move || {
            // the core's set, as the sensors' pumps take it (the start's
            // thread may be lowered to the loader's); the thread only pins
            // itself and makes calls that fail
            crate::caps::restore_core();
            // SAFETY: plain calls with no argument.
            let (pid, tid) = unsafe { (libc::getpid() as u64, libc::gettid() as u64) };
            if tid_tx.send((pid << 32) | tid).is_err() || go_rx.recv().is_err() {
                return;
            }
            for &cpu in &list {
                if halt.load(Ordering::SeqCst) {
                    return;
                }
                let on = pin_to(cpu);
                // the deadline may have passed while the thread waited for
                // the CPU: no call once the probe is no longer its
                if halt.load(Ordering::SeqCst) {
                    return;
                }
                if on {
                    sensor.call();
                }
                if ran_tx.send((cpu, on)).is_err() {
                    return;
                }
            }
        })
        .context("starting the self-test's thread")?;
    let pid_tgid = tid_rx
        .recv_timeout(PROBE_DEADLINE)
        .map_err(|e| anyhow!("the self-test's thread did not start: {e}"))?;
    set_probe(ebpf, round, pid_tgid)?;
    let _ = go_tx.send(());
    let deadline = Instant::now() + PROBE_DEADLINE;
    let mut ran: Vec<(u32, bool)> = Vec::with_capacity(cpus.len());
    while ran.len() < cpus.len() {
        let left = deadline.saturating_duration_since(Instant::now());
        match ran_rx.recv_timeout(left) {
            Ok(r) => ran.push(r),
            Err(_) => break,
        }
    }
    // the thread is no longer the probe's, whatever came back
    stop.store(true, Ordering::SeqCst);
    set_probe(ebpf, round, 0)?;
    let seen = seen_map(ebpf)?;
    Ok(verdicts(cpus, &ran, sensor, point, round, |i| {
        seen.get(&i, 0).ok()
    }))
}

/// The verdict of each CPU of `cpus`: from what the thread `ran` (`true`:
/// pinned there and the call made; `false`: it could not run there) and
/// the marks of `point`'s row, `mark(index)` the map's value there; a CPU
/// the thread did not report is [`Cpu::Late`].
pub fn verdicts(
    cpus: &[u32],
    ran: &[(u32, bool)],
    sensor: Sensor,
    point: Point,
    round: u32,
    mark: impl Fn(u32) -> Option<u32>,
) -> Vec<(u32, Cpu)> {
    cpus.iter()
        .map(|&cpu| match ran.iter().find(|(c, _)| *c == cpu) {
            None => (cpu, Cpu::Late),
            Some((_, false)) => (cpu, Cpu::Unpinned),
            Some((_, true)) => {
                let marked = cpu < SEEN_CPUS
                    && round != 0
                    && mark(sensor.row(point) * SEEN_CPUS + cpu) == Some(round);
                (cpu, if marked { Cpu::Seen } else { Cpu::Missed })
            }
        })
        .collect()
}

/// Pin the calling thread to `cpu` and check it runs there.
fn pin_to(cpu: u32) -> bool {
    if cpu as usize >= libc::CPU_SETSIZE as usize {
        return false;
    }
    // SAFETY: a zeroed `cpu_set_t` with one bit set below CPU_SETSIZE, for
    // the calling thread (pid 0); `sched_getcpu` takes no argument.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu as usize, &mut set);
        if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) != 0 {
            return false;
        }
        // the kernel moves the thread before the call returns; a few
        // yields cover a migration still in flight
        for _ in 0..8 {
            if libc::sched_getcpu() == cpu as libc::c_int {
                return true;
            }
            libc::sched_yield();
        }
        false
    }
}

fn set_probe(ebpf: &mut Ebpf, round: u32, pid_tgid: u64) -> Result<()> {
    let map = ebpf
        .map_mut(PROBE_MAP)
        .ok_or_else(|| anyhow!("map {PROBE_MAP} missing from the eBPF object"))?;
    let mut probe: Array<_, u64> = Array::try_from(map).map_err(|e| anyhow!("{PROBE_MAP}: {e}"))?;
    // the round first: a thread named before its round would mark the old one
    probe
        .set(1, &u64::from(round), 0)
        .map_err(|e| anyhow!("{PROBE_MAP}[1]: {e}"))?;
    probe
        .set(0, &pid_tgid, 0)
        .map_err(|e| anyhow!("{PROBE_MAP}[0]: {e}"))
}

/// Lot 1.3 (the review of #625, P3-5): `point` records `sensor`'s calls
/// from now on, the other attach point marks the self-test's only — one
/// write, so no call is recorded by both.
pub fn set_emitter(ebpf: &mut Ebpf, sensor: Sensor, point: Point) -> Result<()> {
    let map = ebpf
        .map_mut(EMIT_MAP)
        .ok_or_else(|| anyhow!("map {EMIT_MAP} missing from the eBPF object"))?;
    let mut emit: Array<_, u32> = Array::try_from(map).map_err(|e| anyhow!("{EMIT_MAP}: {e}"))?;
    emit.set(sensor.emit_slot(), &point.by(), 0)
        .map_err(|e| anyhow!("{EMIT_MAP}[{}]: {e}", sensor.emit_slot()))
}

fn seen_map(ebpf: &Ebpf) -> Result<Array<&aya::maps::MapData, u32>> {
    let map = ebpf
        .map(SEEN_MAP)
        .ok_or_else(|| anyhow!("map {SEEN_MAP} missing from the eBPF object"))?;
    Array::try_from(map).map_err(|e| anyhow!("{SEEN_MAP}: {e}"))
}

/// The online CPUs, read through the kernel's own view (a mount laid over
/// `/sys` cannot answer for it); the error when the list cannot be read or
/// parsed — the caller signs the self-test as not run, never a default.
pub fn online_cpu_list() -> std::result::Result<Vec<u32>, String> {
    match antitamper_bpf::kernel_roots::read_to_string(ONLINE) {
        Ok(text) => parse_cpu_list(&text)
            .ok_or_else(|| format!("the online CPUs' list {:?} is no CPU list", text.trim())),
        Err(e) => Err(format!("the online CPUs' list could not be read: {e}")),
    }
}

/// The offsets `sensor`'s fallback needs that this kernel's BTF did not
/// give (none: it can be armed).
fn fallback_missing(sensor: Sensor) -> Option<&'static str> {
    let Some(r) = crate::anti_tamper::btf_revalidate::resolved() else {
        return Some("no kernel BTF");
    };
    sensor.fallback_slots().iter().find_map(|(s, name)| {
        match r.values.iter().find(|(k, _)| k == s) {
            Some((_, v)) if *v != BTF_OFFSETS_ABSENT => None,
            _ => Some(*name),
        }
    })
}

fn attach_fallback(ebpf: &mut Ebpf, sensor: Sensor) -> Result<()> {
    if let Some(missing) = fallback_missing(sensor) {
        bail!("{missing} is not resolved on this kernel");
    }
    let name = sensor.fallback_program();
    let prog: &mut RawTracePoint = ebpf
        .program_mut(name)
        .ok_or_else(|| anyhow!("program {name} missing from the eBPF object"))?
        .try_into()
        .with_context(|| format!("program {name} is not a raw tracepoint"))?;
    prog.load()
        .with_context(|| format!("verifier rejected `{name}`"))?;
    prog.attach(RAW_TRACEPOINT)
        .with_context(|| format!("attaching `{name}` to the raw tracepoint {RAW_TRACEPOINT}"))?;
    Ok(())
}

/// Detach and unload the syscall tracepoint `name`, its links retired
/// first so the BPF self-defence does not take their absence for tampering
/// (as the file-open sensor retires `sys_enter_openat` in LSM mode).
fn retire_tracepoint(ebpf: &mut Ebpf, guard: &BpfGuard, name: &str) -> bool {
    match ebpf.program_mut(name).map(<&mut TracePoint>::try_from) {
        Some(Ok(p)) => {
            if let Ok(info) = p.info() {
                guard.retire_program_links(info.id());
            }
            p.unload().is_ok()
        }
        _ => false,
    }
}

/// [`retire_tracepoint`] for the raw tracepoint fallback `name`.
fn retire_raw(ebpf: &mut Ebpf, guard: &BpfGuard, name: &str) -> bool {
    match ebpf.program_mut(name).map(<&mut RawTracePoint>::try_from) {
        Some(Ok(p)) => {
            if let Ok(info) = p.info() {
                guard.retire_program_links(info.id());
            }
            p.unload().is_ok()
        }
        _ => false,
    }
}

/// What [`on_every_cpu`] left running.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Taken {
    /// The syscall tracepoint, proven on every online CPU.
    Tracepoint,
    /// The syscall tracepoint, seen on every online CPU but fewer than
    /// [`MIN_CPUS_PROVEN`] of them (one online CPU at the boot): not
    /// proven, signed; it runs on CPU 0.
    NotProven,
    /// The raw `sys_enter` fallback, the tracepoint's coverage and its own
    /// signed.
    Fallback,
    /// The syscall tracepoint, not proven on every CPU (the fallback not
    /// attached or no better), signed.
    Partial,
    /// The self-test could not run (signed): the tracepoint stays.
    Untested,
}

/// Lot 324: prove `sensor`'s syscall tracepoint on every online CPU, and
/// take its fallback where it is not — the reasons signed with the
/// sensor's degradation source and the attach point noted. `guard`: the
/// BPF self-defence, told of the links the swap retires.
///
/// Fail-safe (the review of #625): the fallback is judged on its own marks
/// only; it records nothing until it is chosen, then takes over in one
/// write before the tracepoint goes; a switch that fails keeps the
/// tracepoint. The test runs once, at the boot: a CPU brought online later
/// is not tested (`SENSOR_CONTRACT.md` §5c).
pub fn on_every_cpu(
    ebpf: &mut Ebpf,
    sensor: Sensor,
    points: &AttachPoints,
    guard: &BpfGuard,
) -> Taken {
    let tp = sensor.tracepoint_program();
    let cpus = match online_cpu_list() {
        Ok(c) => c,
        Err(e) => return untested(sensor, &e),
    };
    let first = match probe(ebpf, sensor, Point::Tracepoint, &cpus, ROUND_TRACEPOINT) {
        Ok(r) => decide(&r),
        Err(e) => return untested(sensor, &format!("{e:#}")),
    };
    match first.verdict() {
        Verdict::Proven => {
            info!(
                sensor = sensor.manifest_sensor(),
                program = tp,
                cpus = %cpu_list(&first.seen),
                "every-CPU self-test: the syscall tracepoint runs on every online CPU"
            );
            return Taken::Tracepoint;
        }
        Verdict::NotProven => {
            report(
                sensor,
                &format!(
                    "{} on the syscall tracepoint {tp}: {} of the online CPUs {} — not proven: \
                     the boot's every-CPU self-test tested fewer than {MIN_CPUS_PROVEN} CPUs, and \
                     on a kernel that runs such a tracepoint on CPU 0 alone (Ubuntu 26.04's 7.0) \
                     CPU 0 is seen too; kept there (it runs on CPU 0). The test runs at the boot \
                     only: the calls made on a CPU brought online later are not proven observed",
                    sensor.manifest_sensor(),
                    first.describe(),
                    cpu_list(&cpus),
                ),
            );
            return Taken::NotProven;
        }
        Verdict::NotEvery => {}
    }
    warn!(
        sensor = sensor.manifest_sensor(),
        program = tp,
        coverage = %first.describe(),
        "every-CPU self-test: the syscall tracepoint does not run on every online CPU — \
         trying its fallback on the raw sys_enter tracepoint"
    );
    // attached muted: until the switch below, the tracepoint records and
    // the fallback marks the self-test's calls in its own row only
    let fallback = match attach_fallback(ebpf, sensor) {
        Ok(()) => match probe(ebpf, sensor, Point::Fallback, &cpus, ROUND_FALLBACK) {
            Ok(r) => Ok(decide(&r)),
            Err(e) => Err(format!("its self-test could not run ({e:#})")),
        },
        Err(e) => Err(format!("{e:#}")),
    };
    let chosen = choose(&first, fallback.as_ref().ok());
    let lead = format!(
        "{} on the syscall tracepoint {tp}: {} of the online CPUs {} (the boot's every-CPU \
         self-test; on Ubuntu 26.04's 7.0 such a tracepoint runs on CPU 0 alone)",
        sensor.manifest_sensor(),
        first.describe(),
        cpu_list(&cpus),
    );
    let unobserved = cpu_list(&[first.missed.clone(), first.unpinned.clone(), first.late.clone()].concat());
    match (chosen, fallback) {
        (Choice::Fallback, Ok(f)) => {
            // the switch first, in one write: the fallback records from
            // here on, the tracepoint no longer — no call twice, none lost
            if let Err(e) = set_emitter(ebpf, sensor, Point::Fallback) {
                let _ = retire_raw(ebpf, guard, sensor.fallback_program());
                report(
                    sensor,
                    &format!(
                        "{lead} — kept there: its fallback ({}) was {} but could not be made to \
                         record ({e:#}): the calls made on CPUs {unobserved} are not observed",
                        sensor.fallback_program(),
                        f.describe()
                    ),
                );
                return Taken::Partial;
            }
            let left = if retire_tracepoint(ebpf, guard, tp) {
                ""
            } else {
                "; the syscall tracepoint could not be unloaded: it stays attached and records \
                 nothing"
            };
            points.note(
                sensor.manifest_sensor(),
                sensor.fallback_note(),
                Took::Fallback,
            );
            let rest = if f.every() {
                String::new()
            } else {
                format!("; the fallback itself: {}", f.describe())
            };
            report(
                sensor,
                &format!(
                    "{lead} — moved to the raw sys_enter tracepoint ({}), which every system call \
                     of the host passes through{rest}{left}",
                    sensor.fallback_program()
                ),
            );
            Taken::Fallback
        }
        (_, fallback) => {
            let why = match fallback {
                Ok(f) => {
                    let left = if retire_raw(ebpf, guard, sensor.fallback_program()) {
                        ""
                    } else {
                        "; it could not be unloaded: it stays attached and records nothing"
                    };
                    if f.seen.is_empty() {
                        format!("its fallback was seen on no CPU either ({}){left}", f.describe())
                    } else {
                        format!("its fallback covers less ({}){left}", f.describe())
                    }
                }
                Err(e) => {
                    // armed or not, it records nothing (the switch was not made)
                    let _ = retire_raw(ebpf, guard, sensor.fallback_program());
                    format!("its fallback could not be armed ({e})")
                }
            };
            report(
                sensor,
                &format!(
                    "{lead} — kept there, {why}: the calls made on CPUs {unobserved} are not observed"
                ),
            );
            Taken::Partial
        }
    }
}

fn untested(sensor: Sensor, why: &str) -> Taken {
    report(
        sensor,
        &format!(
            "{} on the syscall tracepoint {}: the boot's every-CPU self-test could not run ({why}) — \
             whether the calls made on every CPU are observed is not known",
            sensor.manifest_sensor(),
            sensor.tracepoint_program()
        ),
    );
    Taken::Untested
}

fn report(sensor: Sensor, detail: &str) {
    warn!(
        source = sensor.degradation_source(),
        detail, "sensor degraded"
    );
    crate::boot::degradation::report(sensor.degradation_source(), detail);
}

#[cfg(test)]
mod tests;
