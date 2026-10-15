//! Single-owner eBPF object loader + per-ringbuf pump tasks.
//!
//! Loads the compiled eBPF object once, attaches all six programs
//! (one tracepoint exec + two syscall tracepoints + three kprobes),
//! drains each program's dedicated ringbuf, and funnels every decoded
//! event into a unified [`mpsc`] channel. The agent main loop reads
//! from a single `Receiver<Event>` and stays oblivious to which
//! sensor produced what.
//!
//! Tappa 10 N9 — [`Self::start_with_net`] additionally attaches the
//! three N2 network observation programs (`inet_csk_listen_start`
//! kprobe, `tcp_close` fexit, `udp_sendmsg_outbound` kprobe) and
//! returns the two new ringbufs ([`NetRingBufs`]) for the caller's
//! [`crate::net::drain::drain_loop`] to consume. The TcpConnect +
//! DnsQuery pumps are routed through the feeder-aware variants
//! ([`pump_tcp_connect`] / [`pump_dns_query`]) so the
//! [`FlowTracker`] + [`DnsCache`] receive every connect / DNS
//! query observation BEFORE the corresponding `Event::*` lands on
//! the bus.

use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use aya::{
    maps::{ring_buf::RingBuf, MapData},
    programs::{FExit, KProbe, TracePoint},
    Btf, Ebpf, EbpfLoader,
};
use bytemuck::Pod;
use common::wire::{
    dns_flags, BpfSyscallRaw, DnsQueryRaw, ExecCheckRaw, FileOpenRaw, FsProtectDenialRaw,
    IoUringRaw, ModuleLoadRaw, ProcessSpawnRaw, TcpConnectRaw,
};
use common::Event;
use parking_lot::Mutex;
use tokio::{io::unix::AsyncFd, sync::mpsc, task::JoinHandle};
use tracing::{debug, error, info, warn};

use crate::net::dns_cache::DnsCache;
use crate::net::flow_tracker::{FlowTracker, TcpConnectInfo};
use crate::posture::lineage::AuthSessionTracker;

/// eBPF object embedded once in [`crate::sensors::ebpf_object`] (the
/// single embed site + boot preflight). Re-used here so this loader and
/// the Tappa 1 [`super::exec`] loader load byte-identical bytes.
use crate::sensors::ebpf_object::EBPF_BYTES;
use crate::sensors::reject::RejectThrottle;

/// Channel between the per-ringbuf pumps and the agent main loop.
const CHANNEL_CAPACITY: usize = 4096;

/// Tappa 10 N9 — shared state the multiplexer threads into the
/// TcpConnect + DnsQuery pumps so each kernel observation feeds
/// the userland flow tracker / DNS cache before the corresponding
/// `Event::*` lands on the main-loop bus.
#[derive(Clone)]
pub struct NetWiring {
    pub flow_tracker: Arc<Mutex<FlowTracker>>,
    pub dns_cache: Arc<DnsCache>,
    /// External audit NETR-008: names the connecting process's image on
    /// every TCP connect (the spawn cache, `/proc` as fallback).
    pub lineage: crate::posture::lineage::AuthSessionTracker,
}

/// Tappa 10 N9 — ringbufs the multiplexer surfaces back to the
/// caller for the [`crate::net::drain::drain_loop`] to own. Held
/// outside the multiplexer because the drain task is the only
/// consumer + we want explicit ownership transfer (rather than
/// the multiplexer's auto-pump pattern, which would hide the
/// FlowTracker / DnsCache feeding inside per-ringbuf decoders).
pub struct NetRingBufs {
    pub close_rb: RingBuf<MapData>,
    pub listen_rb: RingBuf<MapData>,
    /// Review 73: the UDP flow records, apart from the TCP closes.
    pub udp_rb: RingBuf<MapData>,
}

/// Owns the loaded eBPF object and every attached link. Dropping the
/// multiplexer detaches everything and aborts the pump tasks.
pub struct SensorMultiplexer {
    ebpf: Ebpf,
    /// Every long-lived task that moves telemetry (ring pumps, drains, the
    /// open-sensor rule refresher), by label. External audit SNS-001: the
    /// main loop polls [`Self::finished_pumps`]; a task that ended is a
    /// blind spot and stops the agent.
    pumps: Vec<(&'static str, JoinHandle<()>)>,
    rx: mpsc::Receiver<Event>,
    /// Tappa 9 C8: cloneable handle to the same `Event` channel
    /// the sensor pumps feed. The FIM drain loop (also spawned at
    /// agent boot) clones this to push `Event::Fim` items into the
    /// same main-loop receiver — no extra `select!` arm needed in
    /// `main.rs`. Tappa 10 N9 reuses the same pattern for the
    /// net drain loop.
    event_tx: mpsc::Sender<Event>,
}

impl SensorMultiplexer {
    /// Load + attach + start. The returned multiplexer is hot: events
    /// will already be flowing into the channel by the time it
    /// returns. Net observation programs (Tappa 10 N2) are NOT
    /// attached — use [`Self::start_with_net`] for those.
    pub async fn start() -> Result<Self> {
        let (mux, _) = Self::do_start(None).await?;
        Ok(mux)
    }

    /// Tappa 10 N9 — load + attach + start, including the three
    /// N2 network programs. Returns the multiplexer alongside the
    /// two new ringbufs the caller should hand to
    /// [`crate::net::drain::drain_loop`].
    pub async fn start_with_net(net: NetWiring) -> Result<(Self, NetRingBufs)> {
        let (mux, bufs) = Self::do_start(Some(net)).await?;
        let bufs =
            bufs.ok_or_else(|| anyhow!("start_with_net must yield NetRingBufs (invariant)"))?;
        Ok((mux, bufs))
    }

    async fn do_start(net: Option<NetWiring>) -> Result<(Self, Option<NetRingBufs>)> {
        if EBPF_BYTES.is_empty() {
            anyhow::bail!(
                "eBPF program not built: agent/build.rs found no artifact. Run \
                 `cargo xtask build-ebpf` first."
            );
        }

        // Tappa 7 task 6 commit #2: pin the anti-tamper STATE maps
        // by-name to bpffs so a restarted agent reuses the SAME
        // kernel map objects the pinned LSM hooks reference (closes
        // the split-brain regression). `prepare_pin_root` returns
        // `None` on a host without bpffs; we then load unpinned so
        // sensors still run. Only maps declared `#[map]` with a
        // `::pinned(..)` constructor are affected.
        //
        // Event RINGBUFS must stay process-local: a ringbuf carries
        // its consumer/producer position state in the kernel map
        // object, so pinning + reusing one across a restart desyncs
        // the new process's fresh consumer (0-length decode flood —
        // see `FS_FIM_EVENTS` in agent-ebpf/src/fim_watch.rs). The
        // sensor ringbufs (EVENTS, FILE_OPEN_EVENTS, EXEC_CHECK_EVENTS,
        // TCP_CONNECT_EVENTS, DNS_QUERY_EVENTS) and FS_FIM_EVENTS are
        // all `with_byte_size` (unpinned).
        //
        // EXCEPTION: `FS_PROTECT_EVENTS` (agent-ebpf/src/inode_protect.rs)
        // is STILL `::pinned` and so is reused here. It has the same
        // reuse hazard, BUT its producer is the filesystem anti-tamper
        // LSM program attached via a REUSED pinned link (non-transient,
        // anti_tamper/mod.rs `filesystem::attach`), so unpinning the ring
        // alone would split producer (old reused prog → old ring) from
        // consumer (new ring) — a SILENT fs-protect blackout instead of a
        // loud flood. Fixing it means dropping the ring-pin AND the
        // program-link-pin together so both reattach fresh; that is a
        // separate change with anti-tamper-persistence implications and is
        // deliberately deferred. Do not unpin FS_PROTECT_EVENTS in
        // isolation.
        let pin_root = crate::anti_tamper::prepare_pin_root();
        let mut loader = EbpfLoader::new();
        loader.btf(None);
        if let Some(root) = pin_root {
            loader.map_pin_path(root);
            debug!(
                path = %root.display(),
                "anti-tamper: anti-tamper maps will be by-name pinned to bpffs"
            );
        }
        let mut ebpf = loader
            .load(EBPF_BYTES)
            .with_context(|| "loading eBPF object (BTF, maps, programs)")?;
        // External audit ATP-013: every map's id, before the ring buffers
        // and RING_DROPS are taken out of the object below — the BPF guard
        // registers them as the agent's own from this record.
        crate::anti_tamper::bpf_defense::remember_loaded_maps(&ebpf);

        // Multi-kernel, level 1: hand the programs the offsets resolved
        // from THIS kernel's BTF before anything attaches. 0 = nothing
        // published (no BTF) → the map stays unarmed, compiled-in
        // constants apply.
        let armed = crate::anti_tamper::btf_revalidate::arm_btf_offsets(&mut ebpf)
            .with_context(|| "arming the BTF_OFFSETS map")?;
        if armed > 0 {
            info!(
                slots = armed,
                "BTF_OFFSETS map armed with runtime-resolved kernel offsets"
            );
        } else {
            warn!("BTF_OFFSETS map NOT armed — eBPF programs use compiled-in offsets");
        }
        // External audit EBPF-004: read-only from here on, for every process.
        if let Err(e) = crate::anti_tamper::btf_revalidate::freeze_btf_offsets(&ebpf) {
            error!(
                error = format!("{e:#}"),
                "BTF_OFFSETS NOT frozen — a root process could rewrite the kernel offsets the \
                 hooks read while the BPF guard only observes"
            );
        }

        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            debug!(?e, "aya-log not initialised (no logger map exported)");
        }
        crate::sensors::ring_drops::install(&mut ebpf);

        attach_tracepoint(
            &mut ebpf,
            "sched_process_exec",
            "sched",
            "sched_process_exec",
        )?;
        attach_tracepoint(
            &mut ebpf,
            "sys_enter_openat",
            "syscalls",
            "sys_enter_openat",
        )?;
        // Review 69: inert in LSM mode until the LSM sensor takes over (or
        // its fallback turns it on, `main::start_open_sensor`).
        if crate::sensors::open_sensor::tracepoint_wanted() {
            crate::sensors::open_sensor::set_tracepoint_emitting(&mut ebpf, true)?;
        }
        // Tappa 10.9 step 2: the exec sensor on LSM `bprm_check_security`
        // (`--exec-sensor`), or `sys_enter_execve` when the LSM program
        // is not wanted, lacks an offset or is refused. Attached here, so
        // the BPF link self-check covers whichever runs.
        crate::sensors::exe_identity::attach(&mut ebpf, |ebpf| {
            attach_tracepoint(ebpf, "sys_enter_execve", "syscalls", "sys_enter_execve")
        })?;
        // io_uring (Tappa 10.8): soft attach — a kernel built without
        // CONFIG_IO_URING has no such tracepoints and nothing to observe.
        // The submit tracepoint was renamed across kernels (`_sqe` ≤ 6.1,
        // `_req` on 6.8 and RHEL 9): load once, try both names.
        match attach_tracepoint(&mut ebpf, "io_uring_create", "io_uring", "io_uring_create") {
            Ok(()) => match attach_tracepoint_any(
                &mut ebpf,
                "io_uring_submit",
                "io_uring",
                &["io_uring_submit_req", "io_uring_submit_sqe"],
            ) {
                Ok(name) => info!(submit_event = name, "io_uring sensor attached (create + submit tracepoints)"),
                Err(e) => warn!(error = format!("{e:#}"), "io_uring submit tracepoint not attached — ring creations are still observed"),
            },
            Err(e) => warn!(
                error = format!("{e:#}"),
                "io_uring tracepoints not available (CONFIG_IO_URING off?) — the asynchronous I/O channel is NOT observed on this kernel"
            ),
        }
        attach_kprobe(&mut ebpf, "tcp_v4_connect", "tcp_v4_connect")?;
        attach_kprobe(&mut ebpf, "tcp_v6_connect", "tcp_v6_connect")?;
        // Tappa 10.9 step 3: the socket-buffer DNS sensor, or `udp_sendmsg`.
        crate::sensors::dns_sensor::attach(&mut ebpf, attach_kprobe)?;

        // Tappa 10 N9 — attach the three N2 network programs only
        // when the caller passed `NetWiring`. Without a drain task
        // the close + listen ringbufs would fill up + drop events,
        // and the kernel-side observation would waste cycles. Keep
        // start() lean for the existing exec_sensor_live test.
        let net_bufs = if net.is_some() {
            // `tcp_close` is fexit — needs vmlinux BTF for the
            // function signature. Without BTF this fails the start, like
            // the anti-tamper deny hooks do (review 53): BTF is a hard
            // prerequisite, see docs/operator/KERNEL_COMPATIBILITY.md.
            let btf =
                Btf::from_sys_fs().with_context(|| "loading vmlinux BTF for net fexit programs")?;
            attach_kprobe(&mut ebpf, "inet_csk_listen_start", "inet_csk_listen_start")?;
            attach_fexit(&mut ebpf, "tcp_close", &btf)?;
            attach_kprobe(&mut ebpf, "udp_sendmsg_outbound", "udp_sendmsg")?;
            // Review 68: datagrams to IPv6 destinations. Soft: a kernel
            // without IPv6 has nothing to observe there.
            if let Err(e) = attach_kprobe(&mut ebpf, "udpv6_sendmsg_outbound", "udpv6_sendmsg") {
                warn!(
                    error = format!("{e:#}"),
                    "net: udpv6_sendmsg not attached — UDP flows to IPv6 destinations are NOT observed"
                );
            }
            let close_rb = take_ringbuf(&mut ebpf, "NET_FLOW_CLOSE_EVENTS")?;
            let listen_rb = take_ringbuf(&mut ebpf, "NET_LISTEN_EVENTS")?;
            let udp_rb = take_ringbuf(&mut ebpf, "NET_UDP_EVENTS")?;
            info!("net: N2 BPF programs attached (inet_csk_listen_start kprobe + tcp_close fexit + udp_sendmsg_outbound kprobes on udp_sendmsg and udpv6_sendmsg)");
            Some(NetRingBufs {
                close_rb,
                listen_rb,
                udp_rb,
            })
        } else {
            None
        };

        let process_spawn_rb = take_ringbuf(&mut ebpf, "EVENTS")?;
        let file_open_rb = take_ringbuf(&mut ebpf, "FILE_OPEN_EVENTS")?;
        let exec_check_rb = take_ringbuf(&mut ebpf, "EXEC_CHECK_EVENTS")?;
        let tcp_connect_rb = take_ringbuf(&mut ebpf, "TCP_CONNECT_EVENTS")?;
        let dns_query_rb = take_ringbuf(&mut ebpf, "DNS_QUERY_EVENTS")?;
        let fs_protect_rb = take_ringbuf(&mut ebpf, "FS_PROTECT_EVENTS")?;
        // BUG-034: module-load observations → Event::ModuleLoad → R018.
        // Maps exist at load time (before attach), so taking it here is safe.
        let module_load_rb = take_ringbuf(&mut ebpf, "MODULE_LOAD_EVENTS")?;
        let iouring_rb = take_ringbuf(&mut ebpf, "IOURING_EVENTS")?;
        let bpf_syscall_rb = take_ringbuf(&mut ebpf, "BPF_SYSCALL_EVENTS")?;

        let (tx, rx) = mpsc::channel::<Event>(CHANNEL_CAPACITY);
        let flow_tracker_for_tcp = net
            .as_ref()
            .map(|w| (Arc::clone(&w.flow_tracker), w.lineage.clone()));
        let dns_cache_for_dns = net.as_ref().map(|w| Arc::clone(&w.dns_cache));

        let pumps = vec![
            (
                "process_spawn",
                spawn_pump::<ProcessSpawnRaw>("process_spawn", process_spawn_rb, tx.clone()),
            ),
            (
                "file_open",
                spawn_pump::<FileOpenRaw>("file_open", file_open_rb, tx.clone()),
            ),
            (
                "exec_check",
                spawn_pump::<ExecCheckRaw>("exec_check", exec_check_rb, tx.clone()),
            ),
            (
                "tcp_connect",
                spawn_tcp_connect_pump(tcp_connect_rb, flow_tracker_for_tcp, tx.clone()),
            ),
            (
                "dns_query",
                spawn_dns_query_pump(dns_query_rb, dns_cache_for_dns, tx.clone()),
            ),
            (
                "fs_protect",
                spawn_pump::<FsProtectDenialRaw>("fs_protect", fs_protect_rb, tx.clone()),
            ),
            (
                "module_load",
                spawn_module_load_pump(module_load_rb, tx.clone()),
            ),
            ("io_uring", spawn_iouring_pump(iouring_rb, tx.clone())),
            (
                "bpf_syscall",
                spawn_pump::<BpfSyscallRaw>("bpf_syscall", bpf_syscall_rb, tx.clone()),
            ),
        ];

        Ok((
            Self {
                ebpf,
                pumps,
                rx,
                event_tx: tx,
            },
            net_bufs,
        ))
    }

    /// Tappa 9 C8 — mutable access to the underlying [`Ebpf`] object
    /// for the FIM observe-program attach + the WATCHED_PATHS map
    /// population. Boot-time helper called once from `main.rs` after
    /// `attach_anti_tamper`; not intended for repeated runtime use.
    pub fn ebpf_mut(&mut self) -> &mut Ebpf {
        &mut self.ebpf
    }

    /// Tappa 9 C8 — clone of the cross-sensor `Event` channel sender.
    /// The FIM drain loop pushes `Event::Fim` items through this so
    /// they land in the same `next_event()` receiver the main loop
    /// already polls.
    pub fn event_tx(&self) -> mpsc::Sender<Event> {
        self.event_tx.clone()
    }

    /// Tappa 9 C8 — register a spawned telemetry task (the FIM and net
    /// drains, the open-sensor pump and its rule refresher) with the
    /// multiplexer so `Drop` aborts it alongside the sensor pumps, and
    /// [`Self::finished_pumps`] reports it if it ends.
    pub fn register_pump_handle(&mut self, label: &'static str, handle: JoinHandle<()>) {
        self.pumps.push((label, handle));
    }

    /// External audit SNS-001: the labels of the telemetry tasks that have
    /// ended (returned, failed or panicked). They never end while the agent
    /// runs, so any entry is a sensor gone blind. `next_event()` cannot
    /// tell: this struct and the drains hold senders of the channel.
    pub fn finished_pumps(&self) -> Vec<&'static str> {
        finished(&self.pumps)
    }

    /// `debug-trigger` builds only: abort the task registered as `label`,
    /// so the lab can check that a dead pump stops the agent. `false` when
    /// no task has that label.
    #[cfg(feature = "debug-trigger")]
    pub fn debug_abort_pump(&self, label: &str) -> bool {
        let mut found = false;
        for (l, h) in &self.pumps {
            if *l == label {
                h.abort();
                found = true;
            }
        }
        found
    }

    /// Drain the next event. In practice never `None`: this struct and the
    /// drains hold senders (a dead pump is caught by
    /// [`Self::finished_pumps`] instead).
    pub async fn next_event(&mut self) -> Option<Event> {
        self.rx.recv().await
    }

    /// Wire up the Tappa 7 anti-tamper LSM hooks: register the
    /// given PID set in `PROTECTED_PIDS` and attach `task_kill` +
    /// `ptrace_access_check`. Lives on the multiplexer because it
    /// owns the only [`Ebpf`] instance — see
    /// [`crate::anti_tamper`] for the rationale.
    ///
    /// `pids` is a slice (not a single PID) so the watchdog can be
    /// registered alongside the agent in the same call once Tappa 7
    /// task 6 commits #3-4 land.
    pub fn attach_anti_tamper(
        &mut self,
        pids: &[u32],
        keep: &[crate::anti_tamper::ExeIdentity],
    ) -> Result<()> {
        crate::anti_tamper::attach(&mut self.ebpf, pids, keep)
    }
}

impl Drop for SensorMultiplexer {
    fn drop(&mut self) {
        for (_, h) in self.pumps.drain(..) {
            h.abort();
        }
    }
}

/// Labels of the finished handles (a dead pump, see
/// [`SensorMultiplexer::finished_pumps`]).
fn finished(pumps: &[(&'static str, JoinHandle<()>)]) -> Vec<&'static str> {
    pumps
        .iter()
        .filter(|(_, h)| h.is_finished())
        .map(|(l, _)| *l)
        .collect()
}

/// Load `program_name` once and attach it to the first of `names` that
/// exists under `category`; returns the name that took. A tracepoint
/// renamed across kernels must not be retried with a second `load()`
/// (aya: "the program is already loaded").
fn attach_tracepoint_any(
    ebpf: &mut Ebpf,
    program_name: &str,
    category: &str,
    names: &[&'static str],
) -> Result<&'static str> {
    let prog: &mut TracePoint = ebpf
        .program_mut(program_name)
        .ok_or_else(|| anyhow!("program {program_name} missing from eBPF object"))?
        .try_into()
        .with_context(|| format!("program {program_name} is not a tracepoint"))?;
    prog.load()
        .with_context(|| format!("verifier rejected `{program_name}`"))?;
    let mut last: Option<anyhow::Error> = None;
    for name in names {
        match prog.attach(category, name) {
            Ok(_) => return Ok(name),
            Err(e) => {
                debug!(program = program_name, event = %name, error = %e, "tracepoint name not attachable — trying the next");
                last = Some(anyhow!(e));
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("no tracepoint name given"))).with_context(|| {
        perf_attach_hint(&format!(
            "attaching tracepoint {category}/{{{}}}",
            names.join("|")
        ))
    })
}

fn attach_tracepoint(
    ebpf: &mut Ebpf,
    program_name: &str,
    category: &str,
    name: &str,
) -> Result<()> {
    let prog: &mut TracePoint = ebpf
        .program_mut(program_name)
        .ok_or_else(|| anyhow!("program {program_name} missing from eBPF object"))?
        .try_into()
        .with_context(|| format!("program {program_name} is not a tracepoint"))?;
    prog.load()
        .with_context(|| format!("verifier rejected `{program_name}`"))?;
    prog.attach(category, name)
        .with_context(|| perf_attach_hint(&format!("attaching tracepoint {category}/{name}")))?;
    Ok(())
}

/// Context for a perf_event_open-based attach failure. EACCES under the
/// systemd unit on a Debian-family kernel means its perf_event_paranoid=3
/// patch wants CAP_SYS_ADMIN (CAP_PERFMON is not enough there): say so,
/// with the fix, instead of a bare "Permission denied".
fn perf_attach_hint(what: &str) -> String {
    let paranoid = std::fs::read_to_string("/proc/sys/kernel/perf_event_paranoid")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "?".into());
    format!(
        "{what} (kernel.perf_event_paranoid={paranoid}; if this is EACCES under the hardened \
         unit on a Debian-family kernel, the unit needs CAP_SYS_ADMIN there — install.sh \
         ships northnarrow-agent.service.d/10-debian-perf-paranoid.conf — or set \
         kernel.perf_event_paranoid=2; see docs/operator/KERNEL_COMPATIBILITY.md)"
    )
}

fn attach_kprobe(ebpf: &mut Ebpf, program_name: &str, symbol: &str) -> Result<()> {
    let prog: &mut KProbe = ebpf
        .program_mut(program_name)
        .ok_or_else(|| anyhow!("program {program_name} missing from eBPF object"))?
        .try_into()
        .with_context(|| format!("program {program_name} is not a kprobe"))?;
    prog.load()
        .with_context(|| format!("verifier rejected `{program_name}`"))?;
    prog.attach(symbol, 0)
        .with_context(|| perf_attach_hint(&format!("attaching kprobe to {symbol}")))?;
    Ok(())
}

/// Attach a BTF-aware fexit program. Tappa 10 N2's `tcp_close`
/// uses fexit (vs. kprobe) for byte-counter accuracy — the
/// counters get bumped during `tcp_close()` execution and are
/// only stable at exit. Mirrors the FIM attach pattern but for
/// non-LSM `FExit` programs.
fn attach_fexit(ebpf: &mut Ebpf, program_name: &str, btf: &Btf) -> Result<()> {
    let prog: &mut FExit = ebpf
        .program_mut(program_name)
        .ok_or_else(|| anyhow!("program {program_name} missing from eBPF object"))?
        .try_into()
        .with_context(|| format!("program {program_name} is not an fexit"))?;
    prog.load(program_name, btf)
        .with_context(|| format!("verifier rejected fexit `{program_name}`"))?;
    prog.attach()
        .with_context(|| format!("attaching fexit to {program_name}"))?;
    Ok(())
}

fn take_ringbuf(ebpf: &mut Ebpf, name: &str) -> Result<RingBuf<MapData>> {
    let map = ebpf
        .take_map(name)
        .ok_or_else(|| anyhow!("ringbuf map `{name}` missing from eBPF object"))?;
    RingBuf::try_from(map).map_err(|e| anyhow!("expected `{name}` to be a RINGBUF: {e}"))
}

fn spawn_pump<T>(
    label: &'static str,
    rb: RingBuf<MapData>,
    tx: mpsc::Sender<Event>,
) -> JoinHandle<()>
where
    T: Pod,
    for<'a> Event: From<&'a T>,
{
    tokio::spawn(async move {
        if let Err(e) = pump::<T>(label, rb, tx).await {
            error!(label, error = %e, "ringbuf pump failed");
        }
    })
}

async fn pump<T>(
    label: &'static str,
    rb: RingBuf<MapData>,
    tx: mpsc::Sender<Event>,
) -> std::io::Result<()>
where
    T: Pod,
    for<'a> Event: From<&'a T>,
{
    pump_with(label, rb, tx, |_, e| (e, [None, None])).await
}

/// External audit EBPF-013: io_uring records, followed by the
/// [`Event::SensorFlood`]s a ring creation carries (creations the kernel's
/// record budgets held back since the process's previous one).
fn spawn_iouring_pump(rb: RingBuf<MapData>, tx: mpsc::Sender<Event>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let floods = |raw: &IoUringRaw, e: Event| (e, common::io_uring_floods(raw));
        if let Err(e) = pump_with("io_uring", rb, tx, floods).await {
            error!(label = "io_uring", error = %e, "ringbuf pump failed");
        }
    })
}

/// External audit PROC-005: module loads, their path made absolute — the
/// kernel's walk stops at the root of the `.ko`'s filesystem, which is put
/// back on its mount point ([`module_path_on_host`]).
fn spawn_module_load_pump(rb: RingBuf<MapData>, tx: mpsc::Sender<Event>) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut mounts = crate::sensors::open_sensor::MountTable::load();
        let place = move |raw: &ModuleLoadRaw, mut e: Event| {
            if let Event::ModuleLoad { path: Some(p), .. } = &mut e {
                if raw.path_truncated == 0 {
                    *p = module_path_on_host(&mut mounts, (raw.root_dev, raw.root_ino), p);
                }
            }
            (e, [None, None])
        };
        if let Err(e) = pump_with("module_load", rb, tx, place).await {
            error!(label = "module_load", error = %e, "ringbuf pump failed");
        }
    })
}

/// A module path relative to its filesystem's root, on the host: under the
/// root's mount point, or — a filesystem no mount of this namespace shows
/// (another namespace's, unmounted since) — under a marker that is no
/// module directory, so the load is judged as one from an unknown place.
pub(crate) fn module_path_on_host(
    mounts: &mut crate::sensors::open_sensor::MountTable,
    root: (u64, u64),
    rel: &str,
) -> String {
    match mounts.absolute(root, rel) {
        Some(p) => p,
        None => format!("/(unplaced filesystem {}:{}){rel}", root.0, root.1),
    }
}

async fn pump_with<T>(
    label: &'static str,
    rb: RingBuf<MapData>,
    tx: mpsc::Sender<Event>,
    // The record's event, then any events it carries (External audit
    // EBPF-013: the floods a budgeted record reports).
    mut after: impl FnMut(&T, Event) -> (Event, [Option<Event>; 2]),
) -> std::io::Result<()>
where
    T: Pod,
    for<'a> Event: From<&'a T>,
{
    let mut async_fd = AsyncFd::new(rb)?;
    let mut reject = RejectThrottle::new();
    loop {
        let mut guard = async_fd.readable_mut().await?;
        let inner = guard.get_inner_mut();
        let mut drained = 0u32;
        while let Some(item) = inner.next() {
            drained += 1;
            let bytes: &[u8] = item.as_ref();
            match bytemuck::try_from_bytes::<T>(bytes) {
                Ok(raw) => {
                    let (event, carried) = after(raw, Event::from(raw));
                    if tx.send(event).await.is_err() {
                        return Ok(());
                    }
                    for extra in carried.into_iter().flatten() {
                        if tx.send(extra).await.is_err() {
                            return Ok(());
                        }
                    }
                }
                Err(_e) => reject.record(label, std::mem::size_of::<T>(), bytes.len()),
            }
        }
        guard.clear_ready();
        if drained == 0 {
            reject.flush_idle(label, std::mem::size_of::<T>());
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    }
}

// ── Tappa 10 N9 — feeder-aware TcpConnect + DnsQuery pumps ───────────

fn spawn_tcp_connect_pump(
    rb: RingBuf<MapData>,
    flow_tracker: Option<(Arc<Mutex<FlowTracker>>, AuthSessionTracker)>,
    tx: mpsc::Sender<Event>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = pump_tcp_connect(rb, flow_tracker, tx).await {
            error!(error = %e, "tcp_connect pump failed");
        }
    })
}

async fn pump_tcp_connect(
    rb: RingBuf<MapData>,
    flow_tracker: Option<(Arc<Mutex<FlowTracker>>, AuthSessionTracker)>,
    tx: mpsc::Sender<Event>,
) -> std::io::Result<()> {
    let mut async_fd = AsyncFd::new(rb)?;
    let mut reject = RejectThrottle::new();
    loop {
        let mut guard = async_fd.readable_mut().await?;
        let inner = guard.get_inner_mut();
        let mut drained = 0u32;
        while let Some(item) = inner.next() {
            drained += 1;
            let bytes: &[u8] = item.as_ref();
            match bytemuck::try_from_bytes::<TcpConnectRaw>(bytes) {
                Ok(raw) => {
                    // Feed the userland flow tracker FIRST so the
                    // matching `tcp_close` fexit (drained on the
                    // dedicated NET_FLOW_CLOSE_EVENTS task) can
                    // always find a `PendingFlow` when it looks
                    // up the corr_id. The send-to-bus below is
                    // best-effort — losing it doesn't break flow
                    // correlation.
                    if let Some((ft, lineage)) = flow_tracker.as_ref() {
                        // Resolved before the tracker's lock is taken.
                        let info = tcp_connect_info_from_raw(raw, lineage);
                        ft.lock().on_tcp_connect(&info);
                    }
                    if tx.send(Event::from(raw)).await.is_err() {
                        return Ok(());
                    }
                }
                Err(_e) => reject.record(
                    "tcp_connect",
                    std::mem::size_of::<TcpConnectRaw>(),
                    bytes.len(),
                ),
            }
        }
        guard.clear_ready();
        if drained == 0 {
            reject.flush_idle("tcp_connect", std::mem::size_of::<TcpConnectRaw>());
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    }
}

fn tcp_connect_info_from_raw(raw: &TcpConnectRaw, lineage: &AuthSessionTracker) -> TcpConnectInfo {
    let comm_len = raw
        .comm
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(raw.comm.len());
    TcpConnectInfo {
        start_ns: raw.timestamp_ns,
        sk_ptr: raw.sk_ptr,
        family: raw.family,
        src_addr: decode_addr(raw.family, raw.src_addr),
        src_port: raw.src_port,
        dst_addr: decode_addr(raw.family, raw.dst_addr),
        dst_port: raw.dst_port,
        // The N2 connect kprobe only fires for TCP, but keep proto
        // explicit so the emitted NetFlowEvent.proto matches the
        // tracker's caller-supplied input (design §4.1 contract).
        proto: 6,
        pid: raw.pid,
        uid: raw.uid,
        comm: String::from_utf8_lossy(&raw.comm[..comm_len]).into_owned(),
        // External audit NETR-008: the image is named here, while the
        // process is alive (a spawn-cache read, `/proc` on a miss). Left
        // `None`, NN-L-NET-008 never fired in production, and a forked
        // child of a staged dropper (no exec event) went unjudged.
        exe: lineage.image_path(raw.pid),
        // External audit NET-016: who holds the PID, read while the process
        // runs; the DNS attribution at close ignores the queries older than
        // it (an earlier holder's).
        proc_start_ns: lineage.start_floor_ns(raw.pid).unwrap_or(0),
    }
}

/// The canonical address (external audit NET-001).
fn decode_addr(family: u8, bytes: [u8; 16]) -> std::net::IpAddr {
    common::netaddr::canonical_ip(family, &bytes)
}

/// FP-3 best-effort resolve of a DNS sender's `/proc/<pid>/exe`.
/// Kernel-resolved symlink (never `comm`, which is
/// `prctl(PR_SET_NAME)`-spoofable — and a comm match here would grant a
/// forged resolver kill-immunity, the exact bypass the attribution layer
/// must avoid). Returns `None` when the process has already exited, the
/// link is unreadable, or the path is non-UTF-8; a miss is fail-toward-
/// today (the rule treats a `None` sender as a non-forwarder and acts on
/// it as before). Racy by nature (the PID may be reused between the BPF
/// event and this read) — the same caveat as the FIM drain's
/// `resolve_pid_exe`; the consuming rule only ever uses a positive
/// resolver match to REDIRECT a kill off the forwarder, never to silence
/// detection.
fn resolve_pid_exe(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

fn spawn_dns_query_pump(
    rb: RingBuf<MapData>,
    dns_cache: Option<Arc<DnsCache>>,
    tx: mpsc::Sender<Event>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = pump_dns_query(rb, dns_cache, tx).await {
            error!(error = %e, "dns_query pump failed");
        }
    })
}

async fn pump_dns_query(
    rb: RingBuf<MapData>,
    dns_cache: Option<Arc<DnsCache>>,
    tx: mpsc::Sender<Event>,
) -> std::io::Result<()> {
    let mut async_fd = AsyncFd::new(rb)?;
    let mut reject = RejectThrottle::new();
    loop {
        let mut guard = async_fd.readable_mut().await?;
        let inner = guard.get_inner_mut();
        let mut drained = 0u32;
        while let Some(item) = inner.next() {
            drained += 1;
            let bytes: &[u8] = item.as_ref();
            match bytemuck::try_from_bytes::<DnsQueryRaw>(bytes) {
                Ok(raw) => {
                    let mut event = Event::from(raw);
                    let mut flood = None;
                    if let Event::DnsQuery {
                        pid,
                        uid,
                        comm,
                        exe,
                        query_name,
                        query_type,
                        dns_server,
                        family,
                        timestamp_ns,
                        ..
                    } = &mut event
                    {
                        // FP-3: resolve the UDP/53 SENDER's
                        // `/proc/<pid>/exe` (best-effort, kernel-resolved
                        // symlink — never comm). The DNS rule family uses
                        // it to tell an originator-issued query apart from
                        // a forwarder's relayed leg so a KillProcess
                        // verdict never lands on the local stub resolver.
                        *exe = resolve_pid_exe(*pid);
                        if let Some(cache) = dns_cache.as_ref() {
                            cache.on_dns_query(
                                *pid,
                                query_name.clone(),
                                *query_type,
                                common::netaddr::canonical_ip(*family, dns_server),
                                *timestamp_ns,
                            );
                        }
                        // Review 78: queries the kernel's DNS budgets held
                        // back since this process's previous record.
                        if raw.held != 0 {
                            flood = Some(Event::DnsFlood {
                                pid: *pid,
                                uid: *uid,
                                comm: comm.clone(),
                                exe: exe.clone(),
                                held: u32::from(raw.held),
                                uid_level: raw.flags & dns_flags::RATE_HELD_UID != 0,
                                timestamp_ns: *timestamp_ns,
                            });
                        }
                    }
                    if tx.send(event).await.is_err() {
                        return Ok(());
                    }
                    if let Some(flood) = flood {
                        if tx.send(flood).await.is_err() {
                            return Ok(());
                        }
                    }
                }
                Err(_e) => {
                    reject.record("dns_query", std::mem::size_of::<DnsQueryRaw>(), bytes.len())
                }
            }
        }
        guard.clear_ready();
        if drained == 0 {
            reject.flush_idle("dns_query", std::mem::size_of::<DnsQueryRaw>());
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    }
}

#[cfg(test)]
mod module_path_tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    /// External audit PROC-005: a module path is put on its filesystem's
    /// mount point; a filesystem no mount shows is no module directory.
    #[test]
    fn a_module_path_is_put_on_its_mount_point() {
        let mut mounts = crate::sensors::open_sensor::MountTable::load();
        let m = std::fs::metadata("/").unwrap();
        let root = (
            crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(m.dev()),
            m.ino(),
        );
        assert_eq!(
            module_path_on_host(&mut mounts, root, "/lib/modules/6.8/kernel/x.ko"),
            "/lib/modules/6.8/kernel/x.ko"
        );
        assert_eq!(
            module_path_on_host(&mut mounts, (999_999, 7), "/lib/modules/6.8/kernel/x.ko"),
            "/(unplaced filesystem 999999:7)/lib/modules/6.8/kernel/x.ko"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// External audit SNS-001: a pump that ends — returned, failed or
    /// panicked — is reported by its label; running ones are not.
    #[tokio::test]
    async fn finished_pump_is_reported_by_label() {
        let running = tokio::spawn(std::future::pending::<()>());
        let returned = tokio::spawn(async {});
        let panicked = tokio::spawn(async { panic!("pump panicked") });
        let pumps = vec![
            ("exec_check", running),
            ("fs_protect", returned),
            ("open_sensor", panicked),
        ];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while finished(&pumps).len() < 2 && std::time::Instant::now() < deadline {
            tokio::task::yield_now().await;
        }
        assert_eq!(finished(&pumps), vec!["fs_protect", "open_sensor"]);
        pumps[0].1.abort();
    }

    /// External audit NETR-008: the connect row names the connecting
    /// process's image — the spawn cache first, `/proc` for a process with
    /// no exec event (a forked child) — where it used to be `None`.
    #[test]
    fn a_connect_names_the_connecting_image() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("4242");
        std::fs::create_dir(&dir).unwrap();
        std::os::unix::fs::symlink("/dev/shm/dropper", dir.join("exe")).unwrap();
        let lineage = AuthSessionTracker::new(tmp.path());
        lineage.ingest_spawn(4300, 1, "/usr/bin/curl", 1);

        let mut raw = TcpConnectRaw::zeroed();
        raw.pid = 4242;
        raw.family = common::netaddr::AF_INET;
        raw.dst_port = 8080;
        let info = tcp_connect_info_from_raw(&raw, &lineage);
        assert_eq!(info.exe.as_deref(), Some("/dev/shm/dropper"));

        raw.pid = 4300;
        let info = tcp_connect_info_from_raw(&raw, &lineage);
        assert_eq!(info.exe.as_deref(), Some("/usr/bin/curl"));

        raw.pid = 4301; // gone, never seen
        assert_eq!(tcp_connect_info_from_raw(&raw, &lineage).exe, None);
    }

    /// External audit NET-016: the connect carries the connecting
    /// process's start (here from `/proc`: at most the start it shows) for
    /// the DNS attribution at close; a process already gone carries 0.
    #[test]
    fn a_connect_carries_the_connecting_process_start() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("4242");
        std::fs::create_dir(&dir).unwrap();
        // starttime (field 22) far past any suspended time of the host
        let ticks: u64 = 1_000_000_000;
        std::fs::write(
            dir.join("stat"),
            format!("4242 (a b) S 1 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 {ticks} 0 0\n"),
        )
        .unwrap();
        let lineage = AuthSessionTracker::new(tmp.path());
        // SAFETY: sysconf has no preconditions.
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as u64;
        let shown = ticks * (1_000_000_000 / hz);

        let mut raw = TcpConnectRaw::zeroed();
        raw.pid = 4242;
        raw.family = common::netaddr::AF_INET;
        let start = tcp_connect_info_from_raw(&raw, &lineage).proc_start_ns;
        assert!(start > 0 && start <= shown, "{start} vs {shown}");

        raw.pid = 4301; // gone
        assert_eq!(tcp_connect_info_from_raw(&raw, &lineage).proc_start_ns, 0);
    }
}
