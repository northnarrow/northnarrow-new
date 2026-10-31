//! Single-owner eBPF object loader + per-ringbuf pumps.
//!
//! Loads the compiled eBPF object once, attaches all six programs
//! (one tracepoint exec + two syscall tracepoints + three kprobes),
//! drains each program's dedicated ringbuf, and sends every decoded
//! event onto the event bus. Lab PR 267 (R12a): the bus is a queue per
//! class of events, taken by priority ([`crate::sensors::bus`]), in place
//! of the one `mpsc` channel of 4,096 events every pump shared; the agent
//! main loop reads it through [`SensorMultiplexer::next_event`] and stays
//! oblivious to which sensor produced what. R12b (lab PR 269): each ring's
//! pump is a thread of its own that sends in batches
//! ([`crate::sensors::pump`]), each a source of the bus with its own
//! sequence ([`BusSender::for_source`]).
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

use std::collections::VecDeque;
use std::marker::PhantomData;
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
use nn_model::Event;
use parking_lot::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use crate::sensors::pump::{run_ring, Pump, PumpThread, RingSource, PASS_MAX, POLL_MS};

use crate::net::dns_cache::DnsCache;
use crate::net::flow_tracker::{FlowTracker, TcpConnectInfo};
use crate::posture::lineage::AuthSessionTracker;
use crate::sensors::bus::{BusLosses, BusReceiver, BusSender, BusStats, Received};

/// The DNS record's decode (R09b, lab PR 254: nn-model's until then).
use crate::sensors::dns_sensor::{nss_query_name, query_event};
/// eBPF object embedded once in [`crate::sensors::ebpf_object`] (the
/// single embed site + boot preflight). Re-used here so this loader and
/// the Tappa 1 [`super::exec`] loader load byte-identical bytes.
use crate::sensors::ebpf_object::EBPF_BYTES;
use crate::sensors::reject::RejectThrottle;

/// Lab PR 267 (R12a): the loss recorder's label among the telemetry tasks
/// (a dead recorder would leave the bus's drops unsigned).
pub const BUS_LOSSES_LABEL: &str = "event_bus_losses";

/// The anti-tamper denials' ring (`agent-ebpf/src/inode_protect.rs`).
pub const FS_PROTECT_RING: &str = "FS_PROTECT_EVENTS";
/// Lot 269 (R12b-1): the size [`FS_PROTECT_RING`] is loaded with — 256 KiB,
/// 4,096 denials of 64 bytes (the 56-byte record and the ring's 8-byte
/// header) where the object declares 64 KiB, 1,024. Its pump is a thread
/// blocked in `poll(2)` since R12b-1, and on a saturated CPU a woken thread
/// may wait a scheduler slice before it runs (EEVDF's 3 ms with 4 CPUs on
/// 6.8) — about the time one process's loop of refused operations takes to
/// fill 1,024 (EXP-13's bursts of 1,500 under an open flood); on R12a the
/// pump was a task that a runtime worker already running polled. Four times
/// the room rides out four such waits. The loader sizes the map
/// (`EbpfLoader::map_max_entries`); the eBPF object is unchanged.
pub const FS_PROTECT_RING_BYTES: u32 = 256 * 1024;

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

/// The exec guards' kernel configuration, which the load writes once the
/// exec sensor is attached and before the io_uring, TCP, DNS and network
/// programs attach (R11c, lab PR 264: on the instance the start gives the
/// load, which keeps what it installs; it was a static seam over the
/// guards' process-wide configuration). Wave 4 restructure, R09b (lab PR 254): the seam that
/// lets this loader move to nn-linux while the exec quarantine (lab PR 223)
/// and the exec policy (lab PR 226) stay in the agent, whose
/// `exec_guards::AgentExecGuards` is the one implementation (the agent's
/// `sensors::SensorMultiplexer` names it).
pub trait ExecGuards {
    /// Write the guards' kernel configuration into the loaded object.
    /// `exec_on_lsm`: the exec sensor attached is the LSM one (the guards
    /// hold candidates only then; R11c, lab PR 264: it was a process-wide
    /// `exe_identity::lsm_active`). Not fatal: a guard whose configuration
    /// fails is off, and says so.
    fn install(&mut self, ebpf: &mut Ebpf, exec_on_lsm: bool);
}

/// What the start decided before the load (R11c, lab PR 264): the attach
/// points the command line chose and the exploit guard's task map sizes.
/// They were process-wide switches the start set before the multiplexer
/// started (`exe_identity::want_lsm`, `open_sensor::want_tracepoint`,
/// `dns_sensor::want_skb`, `epg::set_task_map_entries`). `Default` is the
/// command line's defaults.
#[derive(Clone, Debug)]
pub struct LoadPlan {
    /// The exec sensor on LSM `bprm_check_security` (`--exec-sensor lsm`),
    /// else `sys_enter_execve`.
    pub exec_lsm: bool,
    /// `sys_enter_openat` emits from the start (`--file-open-sensor
    /// tracepoint`); otherwise the LSM file-open sensor's start decides
    /// (review 69).
    pub open_tracepoint: bool,
    /// The socket-buffer DNS sensor (`--dns-sensor skb`), else
    /// `udp_sendmsg`.
    pub dns_skb: bool,
    /// The exploit guard's task maps.
    pub epg_task_maps: crate::sensors::epg::TaskMaps,
}

impl Default for LoadPlan {
    fn default() -> Self {
        Self {
            exec_lsm: true,
            open_tracepoint: false,
            dns_skb: true,
            epg_task_maps: crate::sensors::epg::TaskMaps::default(),
        }
    }
}

/// Owns the loaded eBPF object and every attached link. Dropping the
/// multiplexer detaches everything and aborts the pump tasks. `G`: the exec
/// guards its load configures ([`ExecGuards`]).
pub struct SensorMultiplexer<G> {
    ebpf: Ebpf,
    /// Every long-lived task that moves telemetry (ring pumps, drains, the
    /// open-sensor rule refresher), by label. External audit SNS-001: the
    /// main loop polls [`Self::finished_pumps`]; a task that ended is a
    /// blind spot and stops the agent. R12b: the ring pumps are threads.
    pumps: Vec<(&'static str, Pump)>,
    /// Lab PR 267 (R12a): the event bus's receiving end.
    rx: BusReceiver,
    /// Tappa 9 C8: cloneable handle to the same event bus the sensor
    /// pumps feed. The FIM drain loop (also spawned at agent boot) clones
    /// this to push `Event::Fim` items into the same main-loop receiver —
    /// no extra `select!` arm needed in `main.rs`. Tappa 10 N9 reuses the
    /// same pattern for the net drain loop.
    event_tx: BusSender,
    /// Lab PR 267 (R12a): the bus's loss recorder's bindings, and the
    /// lineage the receiver teaches the execs a tamper event overtakes
    /// (the net wiring's; none without it).
    bus_losses: BusLosses,
    lineage: Option<AuthSessionTracker>,
    /// R09b (lab PR 254): the exec guards of the load.
    guards: PhantomData<fn() -> G>,
    /// R11c (lab PR 264): the ring-drop and fail-open samplers the load
    /// started, for the start to bind their audit log and posture
    /// ([`Self::ring_drops`], [`Self::fail_open`]; process-wide setters
    /// until then).
    ring_drops: crate::sensors::ring_drops::RingDrops,
    fail_open: crate::anti_tamper::fail_open::FailOpen,
    /// R11c (lab PR 264): the BPF guard's record of this object's own maps,
    /// programs and links ([`Self::bpf_guard`]; process-wide statics until
    /// then).
    bpf_guard: crate::anti_tamper::bpf_defense::BpfGuard,
    /// R11c (lab PR 264): where each sensor of this object is attached, for
    /// the capability manifest ([`Self::attach_points`]), and what the DNS
    /// sensor armed ([`Self::dns_mode`]); process-wide until then.
    attach_points: crate::boot::manifest::AttachPoints,
    dns_mode: crate::sensors::dns_sensor::DnsMode,
}

impl<G: ExecGuards> SensorMultiplexer<G> {
    /// Load + attach + start. The returned multiplexer is hot: events
    /// will already be flowing onto the bus by the time it
    /// returns. Net observation programs (Tappa 10 N2) are NOT
    /// attached — use [`Self::start_with_net`] for those.
    ///
    /// Lab PR 218: `_verified` is the proof that every integrity check
    /// passed ([`crate::boot::BootSequence::verify_integrity`]; R11b, lab PR
    /// 262: the load, and the by-name pins of the maps it makes, take it).
    pub async fn start(
        plan: &LoadPlan,
        guards: &mut G,
        _verified: &crate::boot::IntegrityVerified,
    ) -> Result<Self> {
        let (mux, _) = Self::do_start(None, plan, guards).await?;
        Ok(mux)
    }

    /// Tappa 10 N9 — load + attach + start, including the three
    /// N2 network programs. Returns the multiplexer alongside the
    /// two new ringbufs the caller should hand to
    /// [`crate::net::drain::drain_loop`].
    ///
    /// Lab PR 218: `_verified` is the proof that every integrity check
    /// passed — the eBPF object, the state directory, the BTF offsets, the
    /// capabilities, the install manifest, the audit log, the BPF LSM
    /// ([`crate::boot::BootSequence::verify_integrity`]; R11b, lab PR 262:
    /// the load, and the by-name pins of the maps it makes, take it).
    pub async fn start_with_net(
        net: NetWiring,
        plan: &LoadPlan,
        guards: &mut G,
        _verified: &crate::boot::IntegrityVerified,
    ) -> Result<(Self, NetRingBufs)> {
        let (mux, bufs) = Self::do_start(Some(net), plan, guards).await?;
        let bufs =
            bufs.ok_or_else(|| anyhow!("start_with_net must yield NetRingBufs (invariant)"))?;
        Ok((mux, bufs))
    }

    async fn do_start(
        net: Option<NetWiring>,
        plan: &LoadPlan,
        guards: &mut G,
    ) -> Result<(Self, Option<NetRingBufs>)> {
        if EBPF_BYTES.is_empty() {
            anyhow::bail!(
                "eBPF program not built: crates/nn-linux/build.rs found no artifact. Run \
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
        // Event RINGBUFS are process-local, one per boot of the agent:
        // a ringbuf carries its consumer/producer positions in the
        // kernel map object, so pinning + reusing one across a restart
        // desyncs the new process's fresh consumer (0-length decode
        // flood — see `FS_FIM_EVENTS` in agent-ebpf/src/fim_watch.rs).
        // Every `*_EVENTS` ring in agent-ebpf is `with_byte_size`
        // (unpinned); `tests::no_event_ring_is_pinned` holds that.
        //
        // External audit SNS-015: `FS_PROTECT_EVENTS`
        // (agent-ebpf/src/inode_protect.rs) is one of them since the
        // BUG-024 fix. Until then it was pinned and reused, and replayed
        // stale denials after a restart (BUG-024). Its producers — the
        // `inode_*` deny hooks, and `task_kill` / `ptrace_access_check`
        // through `emit_task_denial` (review 62) — are attached fresh
        // every boot (`reattach_fresh`, from `anti_tamper::attach` and
        // `filesystem::attach`), bound to this boot's ring, so no
        // program of an earlier boot writes into a ring nobody reads.
        let pin_root = crate::anti_tamper::prepare_pin_root();
        let mut loader = EbpfLoader::new();
        loader.btf(None);
        // Lab PR 219: the exploit guard's task maps. Strict's sized from
        // pid_max (or --exploit-guard-tasks), not preallocated; lite's (an
        // LRU map, always preallocated) bounded, one entry unless lite runs.
        loader.map_max_entries(
            crate::sensors::epg::STRICT_TASKS_MAP,
            plan.epg_task_maps.strict,
        );
        loader.map_max_entries(crate::sensors::epg::LITE_TASKS_MAP, plan.epg_task_maps.lite);
        // Lot 269: the denials' ring four times the object's (see
        // `FS_PROTECT_RING_BYTES`: a pump thread's wake-up on a busy CPU).
        loader.map_max_entries(FS_PROTECT_RING, FS_PROTECT_RING_BYTES);
        if let Some(root) = pin_root {
            loader.default_map_pin_directory(root);
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
        // registers them as the agent's own from this record (R11c, lab PR
        // 264: the object's own record).
        let bpf_guard = crate::anti_tamper::bpf_defense::BpfGuard::new();
        bpf_guard.remember_loaded_maps(&ebpf);

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
            let btf = std::path::Path::new("/sys/kernel/btf/vmlinux").exists();
            warn!(
                vmlinux_btf = btf,
                "{}",
                btf_offsets_unarmed_warning(btf, net.is_some())
            );
        }
        // External audit EBPF-004: read-only from here on, for every process.
        if let Err(e) = crate::anti_tamper::btf_revalidate::freeze_btf_offsets(&ebpf) {
            error!(
                error = format!("{e:#}"),
                "BTF_OFFSETS NOT frozen — a root process could rewrite the kernel offsets the \
                 hooks read while the BPF guard only observes"
            );
        }

        let ring_drops = crate::sensors::ring_drops::install(&mut ebpf);
        // Lab PR 215: the deny hooks' fail-open counters.
        let fail_open = crate::anti_tamper::fail_open::install(&mut ebpf);
        // Lab PR 164: FLOW_SOCK_MAP's occupancy for `nn-admin net status`.
        crate::sensors::flow_sock::install(&mut ebpf);

        let attach_points = crate::boot::manifest::AttachPoints::new();
        attach_exec_tracepoint(&mut ebpf, &attach_points)?;
        attach_tracepoint(
            &mut ebpf,
            "sys_enter_openat",
            "syscalls",
            "sys_enter_openat",
        )?;
        // Review 69: inert in LSM mode until the LSM sensor takes over (or
        // its fallback turns it on, `main::start_open_sensor`).
        if plan.open_tracepoint {
            crate::sensors::open_sensor::set_tracepoint_emitting(&mut ebpf, true)?;
        }
        attach_points.note(
            "file_open",
            "tracepoint:syscalls/sys_enter_openat (user memory)",
        );
        // Tappa 10.9 step 2: the exec sensor on LSM `bprm_check_security`
        // (`--exec-sensor`), or `sys_enter_execve` when the LSM program
        // is not wanted, lacks an offset or is refused. Attached here, so
        // the BPF link self-check covers whichever runs.
        let exec_program = crate::sensors::exe_identity::attach(
            &mut ebpf,
            plan.exec_lsm,
            &attach_points,
            |ebpf| attach_tracepoint(ebpf, "sys_enter_execve", "syscalls", "sys_enter_execve"),
        )?;
        // Lab PRs 223 and 226 (EXPERIMENTAL): the exec guards' kernel
        // configuration, once the exec sensor's mode is known (R09b, lab PR
        // 254: the agent's, through [`ExecGuards`]).
        guards.install(
            &mut ebpf,
            exec_program == crate::sensors::exe_identity::EXEC_LSM_PROGRAM,
        );
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
                Ok(name) => {
                    info!(
                        submit_event = name,
                        "io_uring sensor attached (create + submit tracepoints)"
                    );
                    attach_points.note(
                        "io_uring",
                        &format!("tracepoint:io_uring/io_uring_create+{name}"),
                    );
                }
                Err(e) => {
                    warn!(error = format!("{e:#}"), "io_uring submit tracepoint not attached — ring creations are still observed");
                    attach_points.note("io_uring", "tracepoint:io_uring/io_uring_create only");
                    // Lab PR 218 (P0 C-13): a fallback is signed, not only a WARN.
                    crate::boot::degradation::report(
                        "io_uring_sensor",
                        "the io_uring submit tracepoint is not attached: ring creations are observed, \
                         the operations submitted through them are not",
                    );
                }
            },
            Err(e) => {
                warn!(
                    error = format!("{e:#}"),
                    "io_uring tracepoints not available (CONFIG_IO_URING off?) — the asynchronous I/O channel is NOT observed on this kernel"
                );
                attach_points.note("io_uring", "not attached");
                crate::boot::degradation::report(
                    "io_uring_sensor",
                    "no io_uring tracepoint on this kernel: the asynchronous I/O channel is not \
                     observed",
                );
            }
        }
        attach_kprobe(&mut ebpf, "tcp_v4_connect", "tcp_v4_connect")?;
        attach_kprobe(&mut ebpf, "tcp_v6_connect", "tcp_v6_connect")?;
        attach_points.note("tcp_connect", "kprobe:tcp_v4_connect+tcp_v6_connect");
        // Tappa 10.9 step 3: the socket-buffer DNS sensor, or `udp_sendmsg`.
        let dns_mode = crate::sensors::dns_sensor::attach(
            &mut ebpf,
            plan.dns_skb,
            &attach_points,
            attach_kprobe,
        )?;

        // Tappa 10 N9 — attach the three N2 network programs only
        // when the caller passed `NetWiring`. Without a drain task
        // the close + listen ringbufs would fill up + drop events,
        // and the kernel-side observation would waste cycles. Keep
        // start() lean for the existing exec_sensor_live test.
        let net_bufs = if net.is_some() {
            // Lab PR 229: names resolved through systemd-resolved's NSS
            // module, for the DNS attribution (optional).
            crate::sensors::dns_sensor::attach_nss(&mut ebpf, &attach_points);
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
            let udp6 = match attach_kprobe(&mut ebpf, "udpv6_sendmsg_outbound", "udpv6_sendmsg") {
                Ok(()) => "+udpv6_sendmsg",
                Err(e) => {
                    warn!(
                        error = format!("{e:#}"),
                        "net: udpv6_sendmsg not attached — UDP flows to IPv6 destinations are NOT observed"
                    );
                    crate::boot::degradation::report(
                        "net_sensor",
                        "udpv6_sendmsg not attached: UDP flows to IPv6 destinations are not observed",
                    );
                    ""
                }
            };
            attach_points.note(
                "net_flows",
                &format!("kprobe:inet_csk_listen_start, fexit:tcp_close, kprobe:udp_sendmsg{udp6}"),
            );
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
        let fs_protect_rb = take_ringbuf(&mut ebpf, FS_PROTECT_RING)?;
        // BUG-034: module-load observations → Event::ModuleLoad → R018.
        // Maps exist at load time (before attach), so taking it here is safe.
        let module_load_rb = take_ringbuf(&mut ebpf, "MODULE_LOAD_EVENTS")?;
        let iouring_rb = take_ringbuf(&mut ebpf, "IOURING_EVENTS")?;
        let bpf_syscall_rb = take_ringbuf(&mut ebpf, "BPF_SYSCALL_EVENTS")?;

        let (tx, rx) = crate::sensors::bus::channel();
        let bus_losses = BusLosses::default();
        let lineage_for_bus = net.as_ref().map(|w| w.lineage.clone());
        let flow_tracker_for_tcp = net.as_ref().map(|w| ConnectWiring {
            flow_tracker: Arc::clone(&w.flow_tracker),
            lineage: w.lineage.clone(),
            dns_cache: Arc::clone(&w.dns_cache),
        });
        let dns_cache_for_dns = net.as_ref().map(|w| Arc::clone(&w.dns_cache));
        // External audit SNS-014: the DNS pump names a sender through the
        // lineage tracker (its spawn cache, `/proc` checked against the
        // query's time); without net wiring, a tracker of its own on `/proc`.
        let lineage_for_dns = net
            .as_ref()
            .map_or_else(AuthSessionTracker::for_host, |w| w.lineage.clone());

        // R12b (lab PR 269): each ring's pump on a thread of its own, a
        // source of the bus of its own; a wait for room runs on the
        // runtime's timers.
        let rt = tokio::runtime::Handle::current();
        let pumps = vec![
            (
                "process_spawn",
                Pump::Thread(spawn_ring_pump::<ProcessSpawnRaw>(
                    "process_spawn",
                    process_spawn_rb,
                    &tx,
                    &rt,
                    no_carry::<ProcessSpawnRaw>,
                )?),
            ),
            (
                "file_open",
                Pump::Thread(spawn_ring_pump::<FileOpenRaw>(
                    "file_open",
                    file_open_rb,
                    &tx,
                    &rt,
                    no_carry::<FileOpenRaw>,
                )?),
            ),
            (
                "exec_check",
                Pump::Thread(spawn_ring_pump::<ExecCheckRaw>(
                    "exec_check",
                    exec_check_rb,
                    &tx,
                    &rt,
                    no_carry::<ExecCheckRaw>,
                )?),
            ),
            (
                "tcp_connect",
                Pump::Thread(spawn_tcp_connect_pump(
                    tcp_connect_rb,
                    flow_tracker_for_tcp,
                    &tx,
                    &rt,
                )?),
            ),
            (
                "dns_query",
                Pump::Thread(spawn_dns_query_pump(
                    dns_query_rb,
                    dns_cache_for_dns,
                    lineage_for_dns,
                    &tx,
                    &rt,
                )?),
            ),
            (
                "fs_protect",
                Pump::Thread(spawn_ring_pump::<FsProtectDenialRaw>(
                    "fs_protect",
                    fs_protect_rb,
                    &tx,
                    &rt,
                    no_carry::<FsProtectDenialRaw>,
                )?),
            ),
            (
                "module_load",
                Pump::Thread(spawn_module_load_pump(module_load_rb, &tx, &rt)?),
            ),
            (
                "io_uring",
                Pump::Thread(spawn_iouring_pump(iouring_rb, &tx, &rt)?),
            ),
            (
                "bpf_syscall",
                Pump::Thread(spawn_ring_pump::<BpfSyscallRaw>(
                    "bpf_syscall",
                    bpf_syscall_rb,
                    &tx,
                    &rt,
                    no_carry::<BpfSyscallRaw>,
                )?),
            ),
            // Lab PR 267 (R12a): the bus's drops, WARNed, signed, raised.
            (
                BUS_LOSSES_LABEL,
                Pump::Task(crate::sensors::bus::spawn_loss_recorder(
                    tx.stats(),
                    bus_losses.clone(),
                )),
            ),
        ];

        Ok((
            Self {
                ebpf,
                pumps,
                rx,
                event_tx: tx,
                bus_losses,
                lineage: lineage_for_bus,
                guards: PhantomData,
                ring_drops,
                fail_open,
                bpf_guard,
                attach_points,
                dns_mode,
            },
            net_bufs,
        ))
    }

    /// R11c (lab PR 264): where each sensor of this object is attached: the
    /// start notes the file-open sensor's move there and lists them in the
    /// capability manifest.
    pub fn attach_points(&self) -> &crate::boot::manifest::AttachPoints {
        &self.attach_points
    }

    /// R11c (lab PR 264): what the DNS sensor armed (the start signs the
    /// `udp_sendmsg` fallback's degradation).
    pub fn dns_mode(&self) -> crate::sensors::dns_sensor::DnsMode {
        self.dns_mode
    }

    /// R11c (lab PR 264): the BPF guard's record of this object's own
    /// objects: the start spawns its link self-check and signs its foreign
    /// pins once the audit log exists, retires a link it detaches, and
    /// marks the stop.
    pub fn bpf_guard(&self) -> &crate::anti_tamper::bpf_defense::BpfGuard {
        &self.bpf_guard
    }

    /// R11c (lab PR 264): the ring-drop sampler the load started, whose
    /// audit log and posture the start binds once they exist.
    pub fn ring_drops(&self) -> &crate::sensors::ring_drops::RingDrops {
        &self.ring_drops
    }

    /// R11c (lab PR 264): the deny hooks' fail-open sampler the load
    /// started, whose audit log the start binds once it exists.
    pub fn fail_open(&self) -> &crate::anti_tamper::fail_open::FailOpen {
        &self.fail_open
    }

    /// Tappa 9 C8 — mutable access to the underlying [`Ebpf`] object
    /// for the FIM observe-program attach + the WATCHED_PATHS map
    /// population. Boot-time helper called once from `main.rs` after
    /// `attach_anti_tamper`; not intended for repeated runtime use.
    pub fn ebpf_mut(&mut self) -> &mut Ebpf {
        &mut self.ebpf
    }

    /// Tappa 9 C8 — clone of the cross-sensor event bus's sender.
    /// The FIM drain loop pushes `Event::Fim` items through this so
    /// they land in the same `next_event()` receiver the main loop
    /// already polls.
    pub fn event_tx(&self) -> BusSender {
        self.event_tx.clone()
    }

    /// R12b (lab PR 269): a sender of the bus for the source `name` (the
    /// FIM and network drains, the open sensor): its envelopes name it,
    /// with a sequence of its own.
    pub fn event_tx_for(&self, name: &'static str) -> BusSender {
        self.event_tx.for_source(name)
    }

    /// Lab PR 267 (R12a): the event bus's counts per queue, for the status.
    pub fn bus_stats(&self) -> BusStats {
        self.rx.stats()
    }

    /// Lab PR 267 (R12a): the bus's loss recorder, whose audit log and
    /// posture the start binds once they exist (as the ring-drop
    /// sampler's), and which the stop flushes.
    pub fn bus_losses(&self) -> &BusLosses {
        &self.bus_losses
    }

    /// Lab PR 267 (R12a): the event the loop took last is decided (its
    /// latency, queue to decision, is counted).
    pub fn decided(&mut self) {
        self.rx.decided();
    }

    /// Review #471 M3: the event loop stops — the bus takes no event any
    /// more and refuses the pumps' sends; the events still queued are
    /// counted in a signed `event_bus_stop` row, and every drop not yet
    /// signed is signed ([`BusLosses::stop`]). The counts, P0 first.
    pub fn stop_bus(&mut self) -> [u64; nn_core::bus::QUEUES] {
        let queued = self.rx.close();
        self.bus_losses.stop(&self.rx.stats(), queued);
        queued
    }

    /// Tappa 9 C8 — register a spawned telemetry task (the FIM and net
    /// drains, the open-sensor pump and its rule refresher) with the
    /// multiplexer so `Drop` aborts it alongside the sensor pumps, and
    /// [`Self::finished_pumps`] reports it if it ends.
    pub fn register_pump_handle(&mut self, label: &'static str, handle: JoinHandle<()>) {
        self.pumps.push((label, Pump::Task(handle)));
    }

    /// R12b (lab PR 269): register a pump on a thread of its own (the open
    /// sensor's), as [`Self::register_pump_handle`] a task.
    pub fn register_pump_thread(&mut self, label: &'static str, pump: PumpThread) {
        self.pumps.push((label, Pump::Thread(pump)));
    }

    /// External audit SNS-001: the labels of the telemetry tasks that have
    /// ended (returned, failed or panicked). They never end while the agent
    /// runs, so any entry is a sensor gone blind. `next_event()` cannot
    /// tell: this struct and the drains hold senders of the bus.
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
                h.stop();
                found = true;
            }
        }
        found
    }

    /// Drain the next event, by priority (lab PR 267, R12a: the bus). In
    /// practice never `None`: this struct and the drains hold senders (a
    /// dead pump is caught by [`Self::finished_pumps`] instead). A tamper
    /// event comes with the execs it overtook ([`Received::overtaken`]),
    /// which the lineage has learned already; the event loop teaches the
    /// engine's rules (`RuleEngine::observe_arrival`) before judging it.
    pub async fn next_event(&mut self) -> Option<Received> {
        self.rx.recv_with(self.lineage.as_ref()).await
    }

    /// Lab PR 219: attach the exploit post-condition guard (detect mode)
    /// and pump its records onto the event bus; the running guard goes
    /// to the start (R11c, lab PR 264: its response and its audit log).
    /// `Err(reason)` when it does not run; nothing of it is attached then.
    /// `_verified`: as for [`Self::start_with_net`] (R11b, lab PR 262).
    pub fn attach_exploit_guard(
        &mut self,
        _verified: &crate::boot::IntegrityVerified,
        variant: crate::sensors::epg::Variant,
    ) -> std::result::Result<crate::sensors::epg::ExploitGuard, String> {
        let (ring, guard) = crate::sensors::epg::attach(&mut self.ebpf, variant)?;
        let pump = spawn_ring_pump::<common::wire::epg::EpgEventRaw>(
            crate::sensors::epg::PUMP_LABEL,
            ring,
            &self.event_tx,
            &tokio::runtime::Handle::current(),
            no_carry::<common::wire::epg::EpgEventRaw>,
        )
        .map_err(|e| format!("its pump's thread did not start: {e:#}"))?;
        self.register_pump_thread(crate::sensors::epg::PUMP_LABEL, pump);
        Ok(guard)
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
    ///
    /// Lab PR 218: `verified` as for [`Self::start_with_net`] (R11b, lab PR
    /// 262: the pins and the deny hooks' attach take it).
    pub fn attach_anti_tamper(
        &mut self,
        verified: &crate::boot::IntegrityVerified,
        pids: &[u32],
        keep: &[crate::anti_tamper::ExeIdentity],
    ) -> Result<crate::anti_tamper::AttachReport> {
        crate::anti_tamper::attach(verified, &mut self.ebpf, &self.bpf_guard, pids, keep)
    }
}

impl<G> Drop for SensorMultiplexer<G> {
    fn drop(&mut self) {
        for (_, h) in self.pumps.drain(..) {
            h.stop();
        }
    }
}

/// Labels of the finished handles (a dead pump, see
/// [`SensorMultiplexer::finished_pumps`]).
fn finished(pumps: &[(&'static str, Pump)]) -> Vec<&'static str> {
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

/// Lab PR 224: R020's evidence lost when `sched_process_exec` is refused.
pub const STDIO_PROBE_DEGRADED: &str = "R020 (shell or interpreter with its standard streams on a \
     network socket) cannot fire: this kernel's verifier refused the standard-stream probes of \
     sched_process_exec, which runs without them (exec records say \"not read\")";

/// The process-spawn sensor: `sched_process_exec`, or — when the kernel's
/// verifier refuses it — `sched_process_exec_nostdio`, the same program
/// without R020's standard-stream probes (lab PR 224, `crate::stdio` in the
/// eBPF crate). The probes are the only part a refusal costs: the exec
/// record keeps flowing, R020's loss is a signed degradation. An attach
/// failure is fatal, as before.
fn attach_exec_tracepoint(
    ebpf: &mut Ebpf,
    attach_points: &crate::boot::manifest::AttachPoints,
) -> Result<()> {
    const WITH_STDIO: &str = "sched_process_exec";
    const WITHOUT_STDIO: &str = "sched_process_exec_nostdio";
    let program = match load_tracepoint(ebpf, WITH_STDIO).err() {
        None => WITH_STDIO,
        Some(e) => {
            error!(
                error = %crate::sensors::exe_identity::verifier_tail(&e),
                "process spawn sensor: `{WITH_STDIO}` refused — loading it without the standard-stream \
                 probes; R020 cannot fire on this kernel"
            );
            load_tracepoint(ebpf, WITHOUT_STDIO)?;
            crate::boot::degradation::report("stdio_probe", STDIO_PROBE_DEGRADED);
            WITHOUT_STDIO
        }
    };
    let prog: &mut TracePoint = ebpf
        .program_mut(program)
        .ok_or_else(|| anyhow!("program {program} missing from eBPF object"))?
        .try_into()
        .with_context(|| format!("program {program} is not a tracepoint"))?;
    prog.attach("sched", "sched_process_exec")
        .with_context(|| perf_attach_hint("attaching tracepoint sched/sched_process_exec"))?;
    attach_points.note(
        "process_spawn",
        if program == WITH_STDIO {
            "tracepoint:sched/sched_process_exec"
        } else {
            "tracepoint:sched/sched_process_exec (no standard-stream probes: R020 off)"
        },
    );
    Ok(())
}

fn load_tracepoint(ebpf: &mut Ebpf, program_name: &str) -> Result<()> {
    let prog: &mut TracePoint = ebpf
        .program_mut(program_name)
        .ok_or_else(|| anyhow!("program {program_name} missing from eBPF object"))?
        .try_into()
        .with_context(|| format!("program {program_name} is not a tracepoint"))?;
    prog.load()
        .with_context(|| format!("verifier rejected `{program_name}`"))
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

/// External audit SNS-012 (NN-AUD-355): the WARN when nothing armed
/// `BTF_OFFSETS`, exact about why and about what the start does next. It
/// said only "compiled-in offsets", as if the agent then ran: a start
/// without BTF does not complete. With the net sensor (the agent's start)
/// its `tcp_close` fexit cannot load, and the start fails there at the
/// latest; without it (tests, tools) no LSM hook can attach, so
/// `attach_anti_tamper` refuses unless `NN_ANTI_TAMPER_ALLOW_DEGRADED=1`
/// (review 53).
fn btf_offsets_unarmed_warning(vmlinux_btf: bool, with_net: bool) -> &'static str {
    match (vmlinux_btf, with_net) {
        (true, _) => {
            "BTF_OFFSETS map NOT armed — /sys/kernel/btf/vmlinux exists but no offset was \
             resolved from it before this load (a caller without the boot-time resolution, or a \
             read that failed: see `BTF unavailable` above); the programs read kernel structures \
             at their compiled-in offsets"
        }
        (false, true) => {
            "BTF_OFFSETS map NOT armed — no vmlinux BTF on this kernel, so no offset was \
             resolved; this start fails at the latest when the net sensor's tcp_close fexit \
             loads BTF below (BTF is a prerequisite: docs/operator/KERNEL_COMPATIBILITY.md)"
        }
        (false, false) => {
            "BTF_OFFSETS map NOT armed — no vmlinux BTF on this kernel, so no offset was \
             resolved and the programs read kernel structures at their compiled-in offsets; no \
             LSM hook can attach, so attach_anti_tamper refuses unless \
             NN_ANTI_TAMPER_ALLOW_DEGRADED=1"
        }
    }
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

/// A record that carries no other event.
fn no_carry<T>(_: &T, e: Event) -> (Event, [Option<Event>; 2]) {
    (e, [None, None])
}

/// R12b (lab PR 269): a ring's pump on a thread of its own, a source of
/// the bus named `label`: each record of type `T` made into its event, and
/// `after` makes it final and adds the events it carries (External audit
/// EBPF-013: the floods a budgeted record reports), sent in batches
/// ([`run_ring`]).
fn spawn_ring_pump<T>(
    label: &'static str,
    rb: RingBuf<MapData>,
    tx: &BusSender,
    rt: &tokio::runtime::Handle,
    mut after: impl FnMut(&T, Event) -> (Event, [Option<Event>; 2]) + Send + 'static,
) -> Result<PumpThread>
where
    T: Pod,
    for<'a> Event: From<&'a T>,
{
    let tx = tx.for_source(label);
    let rt = rt.clone();
    let pump = PumpThread::spawn(label, move |stop| {
        let mut rb = rb;
        let mut decode =
            |bytes: &[u8], out: &mut Vec<Event>| match bytemuck::try_from_bytes::<T>(bytes) {
                Ok(raw) => {
                    let (event, carried) = after(raw, Event::from(raw));
                    out.push(event);
                    out.extend(carried.into_iter().flatten());
                    true
                }
                Err(_) => false,
            };
        run_ring(
            label,
            std::mem::size_of::<T>(),
            &mut rb,
            &tx,
            &rt,
            stop,
            &mut decode,
        )
    })
    .with_context(|| format!("starting the {label} pump's thread"))?;
    Ok(pump)
}

/// External audit EBPF-013: io_uring records, followed by the
/// [`Event::SensorFlood`]s a ring creation carries (creations the kernel's
/// record budgets held back since the process's previous one).
fn spawn_iouring_pump(
    rb: RingBuf<MapData>,
    tx: &BusSender,
    rt: &tokio::runtime::Handle,
) -> Result<PumpThread> {
    let floods = |raw: &IoUringRaw, e: Event| (e, nn_model::io_uring_floods(raw));
    spawn_ring_pump("io_uring", rb, tx, rt, floods)
}

/// External audit PROC-005: module loads, their path made absolute — the
/// kernel's walk stops at the root of the `.ko`'s filesystem, which is put
/// back on its mount point ([`module_path_on_host`]).
fn spawn_module_load_pump(
    rb: RingBuf<MapData>,
    tx: &BusSender,
    rt: &tokio::runtime::Handle,
) -> Result<PumpThread> {
    let mut mounts: Option<crate::sensors::open_sensor::MountTable> = None;
    let place = move |raw: &ModuleLoadRaw, mut e: Event| {
        if let Event::ModuleLoad { path: Some(p), .. } = &mut e {
            if raw.path_truncated == 0 {
                let m = mounts.get_or_insert_with(crate::sensors::open_sensor::MountTable::load);
                *p = module_path_on_host(m, (raw.root_dev, raw.root_ino), p);
            }
        }
        (e, [None, None])
    };
    spawn_ring_pump("module_load", rb, tx, rt, place)
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

// ── Tappa 10 N9 — feeder-aware TcpConnect + DnsQuery pumps ───────────

/// What the connect pump feeds and reads: the flow tracker, the image of
/// the connecting process, and (lab PR 224) the DNS name of the
/// destination for the connect-time row.
struct ConnectWiring {
    flow_tracker: Arc<Mutex<FlowTracker>>,
    lineage: AuthSessionTracker,
    dns_cache: Arc<DnsCache>,
}

/// The connect pump (R12b: a thread of its own, a source of the bus).
fn spawn_tcp_connect_pump(
    rb: RingBuf<MapData>,
    wiring: Option<ConnectWiring>,
    tx: &BusSender,
    rt: &tokio::runtime::Handle,
) -> Result<PumpThread> {
    let tx = tx.for_source("tcp_connect");
    let rt = rt.clone();
    PumpThread::spawn("tcp_connect", move |stop| {
        let mut rb = rb;
        pump_tcp_connect(&mut rb, wiring, &tx, &rt, stop)
    })
    .context("starting the tcp_connect pump's thread")
}

/// Lab PR 246: held by the connect pump while it runs, so the net drain's
/// closes wait for the connects it announces ([`send_connects`]) — and
/// stop waiting when it ends.
struct ConnectPumpClaim(Arc<Mutex<FlowTracker>>);

impl ConnectPumpClaim {
    fn new(tracker: &Arc<Mutex<FlowTracker>>) -> Self {
        tracker.lock().set_connect_pump(true);
        Self(Arc::clone(tracker))
    }
}

impl Drop for ConnectPumpClaim {
    fn drop(&mut self) {
        self.0.lock().set_connect_pump(false);
    }
}

/// Connect records on the bus ([`connect_events`], in order, in batches),
/// then, lab PR 246, announced to the flow tracker: each one's close, held
/// by the net drain until then, follows it on the bus. `false` when the
/// bus is closed.
fn send_connects(
    raws: &[TcpConnectRaw],
    wiring: Option<&ConnectWiring>,
    tx: &BusSender,
    rt: &tokio::runtime::Handle,
) -> bool {
    for chunk in raws.chunks(crate::sensors::bus::BATCH_MAX / 2) {
        let events: Vec<Event> = chunk
            .iter()
            .flat_map(|raw| connect_events(raw, wiring))
            .collect();
        if tx.send_batch_blocking(rt, events).is_err() {
            return false;
        }
        if let Some(w) = wiring {
            let mut tracker = w.flow_tracker.lock();
            for raw in chunk {
                tracker.announce(&FlowTracker::corr_id(raw.timestamp_ns, raw.sk_ptr));
            }
        }
    }
    true
}

fn pump_tcp_connect(
    ring: &mut dyn RingSource,
    flow_tracker: Option<ConnectWiring>,
    tx: &BusSender,
    rt: &tokio::runtime::Handle,
    stop: &std::sync::atomic::AtomicBool,
) -> std::io::Result<()> {
    let mut reject = RejectThrottle::new();
    let mut batch: Vec<TcpConnectRaw> = Vec::new();
    let _claim = flow_tracker
        .as_ref()
        .map(|w| ConnectPumpClaim::new(&w.flow_tracker));
    let size = std::mem::size_of::<TcpConnectRaw>();
    loop {
        if stop.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(());
        }
        let mut read = 0usize;
        while read < PASS_MAX {
            let got = ring.next_record(
                &mut |bytes| match bytemuck::try_from_bytes::<TcpConnectRaw>(bytes) {
                    Ok(raw) => batch.push(*raw),
                    Err(_e) => reject.record("tcp_connect", size, bytes.len()),
                },
            );
            if !got {
                break;
            }
            read += 1;
        }
        // Lab PR 229: the connect-time rows name the destination's DNS name
        // once the DNS pump has read the queries made before these
        // connects (`DnsIngest`); read later, a query was not there yet.
        if let (Some(w), Some(newest)) = (
            flow_tracker.as_ref(),
            batch.iter().map(|r| r.timestamp_ns).max(),
        ) {
            rt.block_on(w.dns_cache.ingest().caught_up(newest));
        }
        if !send_connects(&batch, flow_tracker.as_ref(), tx, rt) {
            return Ok(());
        }
        batch.clear();
        if read < PASS_MAX {
            reject.flush_idle("tcp_connect", size);
            ring.wait(POLL_MS)?;
        }
    }
}

/// The events one connect record becomes, in bus order.
///
/// - A connect the `socket_connect` deny refused (lab PR 224, CM-02 c):
///   its [`nn_model::telemetry::FlowPhase::Denied`] row only — no flow exists,
///   nothing is pending.
/// - A connect: the flow tracker is fed FIRST, so the matching
///   `tcp_close` fexit (drained on the NET_FLOW_CLOSE_EVENTS task) always
///   finds its pending flow; then `Event::TcpConnect` (posture, canary,
///   fan-out rules); then (lab PR 224, CM-02 a) the flow's connect-time
///   row, with the image named now and the DNS name of its destination,
///   for the rules that need no byte count to judge it while it is open.
///   Once both are on the bus the pump announces the connect (lab PR 246,
///   [`send_connects`]): the net drain holds its close until then.
///   Without net wiring (the exec sensor's live test) only the
///   `TcpConnect`.
fn connect_events(raw: &TcpConnectRaw, wiring: Option<&ConnectWiring>) -> Vec<Event> {
    let Some(w) = wiring else {
        return vec![Event::from(raw)];
    };
    // Resolved before the tracker's lock is taken.
    let info = tcp_connect_info_from_raw(raw, &w.lineage);
    if raw.flags & common::wire::tcp_connect_flags::DENIED != 0 {
        crate::sensors::connect_deny::note_denied();
        let mut row = FlowTracker::denied_row(&info);
        row.resolved_hostname =
            w.dns_cache
                .lookup_for_connect(row.pid, row.start_ns, row.proc_start_ns);
        return vec![Event::NetFlow(row)];
    }
    let row = w.flow_tracker.lock().on_tcp_connect(&info);
    let mut out = vec![Event::from(raw)];
    if let Some(mut row) = row {
        row.resolved_hostname =
            w.dns_cache
                .lookup_for_connect(row.pid, row.start_ns, row.proc_start_ns);
        out.push(Event::NetFlow(row));
    }
    out
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
        // tracker's caller-supplied input (design §4.1 contract). Lab PR
        // 224: a record of the `socket_connect` deny names the socket's
        // protocol (a connected UDP socket is refused too).
        proto: if raw.proto != 0 { raw.proto } else { 6 },
        pid: raw.pid,
        uid: raw.uid,
        comm: String::from_utf8_lossy(&raw.comm[..comm_len]).into_owned(),
        // External audit NETR-008: the image is named here, while the
        // process is alive (a spawn-cache read, `/proc` on a miss). Left
        // `None`, NN-L-NET-008 never fired in production, and a forked
        // child of a staged dropper (no exec event) went unjudged.
        // Review #471 A1: the image at the connect, not a later exec.
        exe: lineage.image_path_at(raw.pid, raw.timestamp_ns),
        // External audit NET-016: who holds the PID, read while the process
        // runs; the DNS attribution at close ignores the queries older than
        // it (an earlier holder's).
        proc_start_ns: lineage.start_floor_ns(raw.pid).unwrap_or(0),
    }
}

/// The canonical address (external audit NET-001).
fn decode_addr(family: u8, bytes: [u8; 16]) -> std::net::IpAddr {
    nn_model::netaddr::canonical_ip(family, &bytes)
}

/// FP-3: the image of a DNS query's sender — never `comm`, which is
/// `prctl(PR_SET_NAME)`-spoofable (a comm match here would grant a forged
/// resolver kill-immunity, the exact bypass the attribution layer must
/// avoid). External audit SNS-014: the ring is drained after the send, and
/// a bare `/proc/<pid>/exe` read then named whatever held the pid at that
/// moment — a later process, or the image the sender executed since. The
/// lineage tracker answers for the sender only
/// ([`AuthSessionTracker::image_at`]): its cached exec when it ran no later
/// than the query, else `/proc/<pid>/exe` when the process `/proc` shows
/// started no later than it. `None` otherwise (gone, reused, executed
/// since): the rule treats an unnamed sender as a non-forwarder and acts on
/// it as before. A positive resolver match only ever REDIRECTS a kill off
/// the forwarder, never silences detection.
fn dns_sender_exe(lineage: &AuthSessionTracker, pid: u32, timestamp_ns: u64) -> Option<String> {
    lineage.image_at(pid, timestamp_ns)
}

/// One DNS record: its `Event::DnsQuery` (the sender's image named, the
/// DNS cache fed), then the `Event::DnsFlood` it carries, if any.
fn dns_events(
    raw: &DnsQueryRaw,
    lineage: &AuthSessionTracker,
    dns_cache: Option<&DnsCache>,
) -> (Event, Option<Event>) {
    let mut event = query_event(raw);
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
        // FP-3: the UDP/53 SENDER's image. The DNS rule family uses it to
        // tell an originator-issued query apart from a forwarder's relayed
        // leg so a KillProcess verdict never lands on the local stub
        // resolver.
        *exe = dns_sender_exe(lineage, *pid, *timestamp_ns);
        if let Some(cache) = dns_cache {
            cache.on_dns_query(
                *pid,
                query_name.clone(),
                *query_type,
                nn_model::netaddr::canonical_ip(*family, dns_server),
                *timestamp_ns,
            );
        }
        // Review 78: queries the kernel's DNS budgets held back since this
        // process's previous record.
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
    (event, flood)
}

/// Lab PR 229: one [`dns_flags::NSS`] record — a name the process asked
/// systemd-resolved for through its NSS module. It feeds the DNS cache
/// only, for the attribution of the process's connects: no
/// `Event::DnsQuery` (no datagram was sent, and the DNS rules judge the
/// queries that go on the wire — systemd-resolved's own for this name),
/// and no server, so the forwarder back-correlation (`originator_for`,
/// local stubs only) does not count it. The `Event::DnsFlood` of the
/// queries the DNS budgets held back, which this record carries as any
/// other would, still goes out.
fn nss_events(
    raw: &DnsQueryRaw,
    lineage: &AuthSessionTracker,
    dns_cache: Option<&DnsCache>,
) -> Option<Event> {
    if let (Some(cache), Some(name)) = (dns_cache, nss_query_name(raw)) {
        cache.on_dns_query(
            raw.pid,
            name,
            0,
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            raw.timestamp_ns,
        );
    }
    (raw.held != 0).then(|| Event::DnsFlood {
        pid: raw.pid,
        uid: raw.uid,
        comm: common::wire::cstr_lossy(&raw.comm).into_owned(),
        exe: dns_sender_exe(lineage, raw.pid, raw.timestamp_ns),
        held: u32::from(raw.held),
        uid_level: raw.flags & dns_flags::RATE_HELD_UID != 0,
        timestamp_ns: raw.timestamp_ns,
    })
}

/// The DNS pump (R12b: a thread of its own, a source of the bus). Its pass
/// answers the lookups' requests (lab PR 229, `DnsIngest::wanted`) as well
/// as its ring's records, so the thread runs the pump's own loop on the
/// runtime's reactor (`Handle::block_on`): woken by either, it sends a
/// pass's events in batches.
fn spawn_dns_query_pump(
    rb: RingBuf<MapData>,
    dns_cache: Option<Arc<DnsCache>>,
    lineage: AuthSessionTracker,
    tx: &BusSender,
    rt: &tokio::runtime::Handle,
) -> Result<PumpThread> {
    // Lab PR 229: the DNS attributions of the net drain and the connect
    // pump wait for this pump's passes while it runs (`DnsIngest`) —
    // claimed here, before any of them can read a record, and released
    // when the pump ends.
    let claim = dns_cache
        .as_ref()
        .map(|c| crate::net::dns_cache::IngestClaim::new(Arc::clone(c)));
    let tx = tx.for_source("dns_query");
    let rt = rt.clone();
    PumpThread::spawn("dns_query", move |stop| {
        let _claim = claim;
        rt.block_on(pump_dns_query(rb, dns_cache, lineage, tx, stop))
    })
    .context("starting the dns_query pump's thread")
}

async fn pump_dns_query(
    rb: RingBuf<MapData>,
    dns_cache: Option<Arc<DnsCache>>,
    lineage: AuthSessionTracker,
    tx: BusSender,
    stop: &std::sync::atomic::AtomicBool,
) -> std::io::Result<()> {
    let mut async_fd = crate::async_fd::register(rb)?;
    let mut reject = RejectThrottle::new();
    // Lab PR 229: a pass feeds the cache with every record it reads, and a
    // lookup's pass is served while the pass's events go out, in ring
    // order. Lab PR 267 (R12a): the bus never makes a network event wait —
    // a full network queue drops the new event and counts it — so they go
    // out as soon as the pass ends; a full bus no longer holds a record,
    // and the cache, behind the send of the one before it (the outbox lab
    // PR 229 kept for that is gone).
    let mut outbox: VecDeque<Event> = VecDeque::new();
    let mut check_stop = tokio::time::interval(std::time::Duration::from_millis(POLL_MS as u64));
    loop {
        if stop.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(());
        }
        let step = tokio::select! {
            r = async_fd.readable_mut() => {
                let mut guard = r?;
                let drained = dns_pass(
                    guard.get_inner_mut(),
                    &lineage,
                    dns_cache.as_deref(),
                    &mut reject,
                    &mut outbox,
                );
                guard.clear_ready();
                if drained == 0 { DnsStep::Idle } else { DnsStep::Read }
            }
            () = async {
                match dns_cache.as_deref() {
                    Some(c) => c.ingest().wanted().await,
                    None => std::future::pending().await,
                }
            } => DnsStep::Asked,
            _ = check_stop.tick() => DnsStep::Tick,
        };
        match step {
            // a lookup asked for a pass: the ring is read, ready or not
            DnsStep::Asked => {
                dns_pass(
                    async_fd.get_mut(),
                    &lineage,
                    dns_cache.as_deref(),
                    &mut reject,
                    &mut outbox,
                );
            }
            DnsStep::Idle => {
                reject.flush_idle("dns_query", std::mem::size_of::<DnsQueryRaw>());
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
            DnsStep::Read | DnsStep::Tick => {}
        }
        // R12b: a pass's events in batches
        while !outbox.is_empty() {
            let n = outbox.len().min(crate::sensors::bus::BATCH_MAX);
            if tx.send_batch(outbox.drain(..n).collect()).await.is_err() {
                return Ok(());
            }
        }
    }
}

/// Lab PR 229: what one turn of the DNS pump did.
enum DnsStep {
    /// Read records.
    Read,
    /// Woken with nothing to read.
    Idle,
    /// A lookup asked for a pass.
    Asked,
    /// R12b: the stop flag's check.
    Tick,
}

/// One pass over the DNS ring, to empty: each record's events into
/// `outbox`, the cache fed. Returns the records read. Lab PR 229: the pass
/// is marked in the cache's [`crate::net::dns_cache::DnsIngest`] with the
/// time it began — every record submitted before it has been read.
fn dns_pass(
    ring: &mut RingBuf<MapData>,
    lineage: &AuthSessionTracker,
    dns_cache: Option<&DnsCache>,
    reject: &mut RejectThrottle,
    outbox: &mut VecDeque<Event>,
) -> u32 {
    let began_ns = crate::net::dns_cache::monotonic_ns();
    let mut drained = 0u32;
    while let Some(item) = ring.next() {
        drained += 1;
        let bytes: &[u8] = item.as_ref();
        match bytemuck::try_from_bytes::<DnsQueryRaw>(bytes) {
            Ok(raw) if raw.flags & dns_flags::NSS != 0 => {
                outbox.extend(nss_events(raw, lineage, dns_cache));
            }
            Ok(raw) => {
                let (event, flood) = dns_events(raw, lineage, dns_cache);
                outbox.push_back(event);
                outbox.extend(flood);
            }
            Err(_e) => reject.record("dns_query", std::mem::size_of::<DnsQueryRaw>(), bytes.len()),
        }
    }
    if let Some(cache) = dns_cache {
        cache.ingest().pass_ended(began_ns);
    }
    drained
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
            ("exec_check", Pump::Task(running)),
            ("fs_protect", Pump::Task(returned)),
            ("open_sensor", Pump::Task(panicked)),
        ];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while finished(&pumps).len() < 2 && std::time::Instant::now() < deadline {
            tokio::task::yield_now().await;
        }
        assert_eq!(finished(&pumps), vec!["fs_protect", "open_sensor"]);
        pumps[0].1.stop();
    }

    fn wiring(lineage: AuthSessionTracker) -> ConnectWiring {
        ConnectWiring {
            flow_tracker: Arc::new(Mutex::new(FlowTracker::default())),
            lineage,
            dns_cache: Arc::new(DnsCache::default()),
        }
    }

    /// Lab PR 224 (CM-02 a): a connect becomes its `TcpConnect` and then
    /// its connect-time row (image and DNS name read now) for the rules,
    /// with the flow pending for its close. The starting tree sent the
    /// `TcpConnect` alone: no rule judged an open flow.
    #[test]
    fn a_connect_is_a_tcp_connect_then_its_open_row() {
        let tmp = tempfile::TempDir::new().unwrap();
        let lineage = AuthSessionTracker::new(tmp.path());
        lineage.ingest_spawn(4500, 1, "/usr/bin/python3.12", 1);
        let w = wiring(lineage);
        w.dns_cache.on_dns_query(
            4500,
            "c2.example".into(),
            1,
            "127.0.0.53".parse().unwrap(),
            9_000,
        );
        let mut raw = TcpConnectRaw::zeroed();
        raw.pid = 4500;
        raw.family = nn_model::netaddr::AF_INET;
        raw.dst_port = 4444;
        raw.dst_addr[..4].copy_from_slice(&[127, 0, 0, 1]);
        raw.timestamp_ns = 10_000;
        raw.sk_ptr = 0xdead;
        let events = connect_events(&raw, Some(&w));
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], Event::TcpConnect { pid: 4500, .. }));
        let Event::NetFlow(row) = &events[1] else {
            panic!("{:?}", events[1]);
        };
        assert_eq!(row.phase, nn_model::telemetry::FlowPhase::Connect);
        assert_eq!(row.exe.as_deref(), Some("/usr/bin/python3.12"));
        assert_eq!(row.resolved_hostname.as_deref(), Some("c2.example"));
        assert_eq!(w.flow_tracker.lock().pending_len(), 1);
        // Without net wiring: the `TcpConnect` alone, as before.
        assert_eq!(connect_events(&raw, None).len(), 1);
        // Review #471 A1: a later exec of the pid, ingested before the
        // connect is read, does not name it — the image as of the connect.
        w.lineage.ingest_spawn(4500, 1, "/usr/sbin/nginx", 20_000);
        let exe_at = |ts: u64, sk: u64| {
            let mut r = raw;
            r.timestamp_ns = ts;
            r.sk_ptr = sk;
            match &connect_events(&r, Some(&w))[1] {
                Event::NetFlow(row) => row.exe.clone(),
                e => panic!("{e:?}"),
            }
        };
        assert_eq!(
            exe_at(10_500, 0xbeef).as_deref(),
            Some("/usr/bin/python3.12")
        );
        assert_eq!(exe_at(30_000, 0xcafe).as_deref(), Some("/usr/sbin/nginx"));
    }

    /// Lab PR 246: a connect is announced to the flow tracker only once its
    /// `TcpConnect` and its connect-time row are on the bus, so the close
    /// the net drain holds for it follows both there. While the pump's
    /// claim is held a close waits; when the pump ends, none does.
    #[test]
    fn a_connect_is_announced_after_its_events_are_on_the_bus() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let tmp = tempfile::TempDir::new().unwrap();
        let w = wiring(AuthSessionTracker::new(tmp.path()));
        let claim = ConnectPumpClaim::new(&w.flow_tracker);
        let mut raw = TcpConnectRaw::zeroed();
        raw.pid = 4700;
        raw.family = nn_model::netaddr::AF_INET;
        raw.dst_port = 41147;
        raw.dst_addr[..4].copy_from_slice(&[127, 0, 0, 1]);
        raw.timestamp_ns = 20_000;
        raw.sk_ptr = 0xbeef;
        let corr = FlowTracker::corr_id(raw.timestamp_ns, raw.sk_ptr);
        assert!(!w.flow_tracker.lock().close_may_proceed(&corr));
        let (tx, mut rx) = crate::sensors::bus::channel();
        assert!(send_connects(&[raw], Some(&w), &tx, rt.handle()));
        assert!(matches!(
            rx.try_recv().map(|r| r.envelope.event),
            Some(Event::TcpConnect { pid: 4700, .. })
        ));
        assert!(matches!(
            rx.try_recv().map(|r| r.envelope.event),
            Some(Event::NetFlow(_))
        ));
        assert!(w.flow_tracker.lock().close_may_proceed(&corr));
        // Another connect, not sent: its close waits until the pump ends.
        let other = FlowTracker::corr_id(30_000, 0xbeef);
        assert!(!w.flow_tracker.lock().close_may_proceed(&other));
        drop(claim);
        assert!(w.flow_tracker.lock().close_may_proceed(&other));
        // A closed bus: not announced.
        drop(rx);
        raw.timestamp_ns = 40_000;
        assert!(!send_connects(&[raw], Some(&w), &tx, rt.handle()));
    }

    /// Lab PR 224 (CM-02 c): a record of the `socket_connect` deny is its
    /// refused row only — no `TcpConnect`, nothing pending — counted, with
    /// the socket's protocol.
    #[test]
    fn a_refused_connect_is_one_denied_row() {
        let tmp = tempfile::TempDir::new().unwrap();
        let w = wiring(AuthSessionTracker::new(tmp.path()));
        let mut raw = TcpConnectRaw::zeroed();
        raw.pid = 4600;
        raw.family = nn_model::netaddr::AF_INET;
        raw.flags = common::wire::tcp_connect_flags::DENIED;
        raw.proto = 17;
        raw.dst_port = 53;
        raw.dst_addr[..4].copy_from_slice(&[192, 0, 2, 7]);
        let events = connect_events(&raw, Some(&w));
        assert_eq!(events.len(), 1);
        let Event::NetFlow(row) = &events[0] else {
            panic!("{:?}", events[0]);
        };
        assert_eq!(row.phase, nn_model::telemetry::FlowPhase::Denied);
        assert_eq!(row.proto, 17);
        assert_eq!(w.flow_tracker.lock().pending_len(), 0);
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
        raw.family = nn_model::netaddr::AF_INET;
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
        raw.family = nn_model::netaddr::AF_INET;
        let start = tcp_connect_info_from_raw(&raw, &lineage).proc_start_ns;
        assert!(start > 0 && start <= shown, "{start} vs {shown}");

        raw.pid = 4301; // gone
        assert_eq!(tcp_connect_info_from_raw(&raw, &lineage).proc_start_ns, 0);
    }

    /// External audit SNS-014: the DNS pump read `/proc/<pid>/exe` when it
    /// drained the record, so a process that took the pid after the query
    /// named the sender — a forwarder's image there redirected the verdict
    /// off the real sender. A later process's image is not used: the
    /// sender is unnamed (a non-forwarder for the rule), and the flood
    /// record it carries says the same.
    #[test]
    fn exe_of_a_later_process_is_not_used() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().join("4242");
        std::fs::create_dir(&dir).unwrap();
        std::os::unix::fs::symlink("/usr/sbin/dnsmasq", dir.join("exe")).unwrap();
        let stat = |ticks: u64| {
            std::fs::write(
                dir.join("stat"),
                format!(
                    "4242 (dnsmasq) S 1 1 1 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 {ticks} 0 0\n"
                ),
            )
            .unwrap()
        };
        // started far later than the query (field 22, in ticks)
        stat(1_000_000_000_000);
        let lineage = AuthSessionTracker::new(tmp.path());
        let mut raw = DnsQueryRaw::zeroed();
        raw.pid = 4242;
        raw.held = 3;
        raw.timestamp_ns = 5_000_000_000;
        let (event, flood) = dns_events(&raw, &lineage, None);
        assert!(
            matches!(event, Event::DnsQuery { exe: None, .. }),
            "{event:?}"
        );
        assert!(matches!(
            flood,
            Some(Event::DnsFlood {
                exe: None,
                held: 3,
                ..
            })
        ));
        // the process that holds the pid started before the query: its own
        stat(1);
        let (event, _) = dns_events(&raw, &lineage, None);
        let Event::DnsQuery { exe, .. } = event else {
            panic!()
        };
        assert_eq!(exe.as_deref(), Some("/usr/sbin/dnsmasq"));
        // gone
        std::fs::remove_dir_all(&dir).unwrap();
        let (event, _) = dns_events(&raw, &lineage, None);
        assert!(matches!(event, Event::DnsQuery { exe: None, .. }));
    }

    /// Lab PR 229: a name asked through systemd-resolved's NSS module (no
    /// datagram: the Debian 13 shape) attributes the asking process's
    /// connect. It is no `Event::DnsQuery`, and the forwarder
    /// back-correlation does not count it; held queries still flag a flood.
    #[test]
    fn an_nss_lookup_feeds_the_attribution_only() {
        let tmp = tempfile::TempDir::new().unwrap();
        let lineage = AuthSessionTracker::new(tmp.path());
        let cache = DnsCache::default();
        let mut raw = DnsQueryRaw::zeroed();
        raw.pid = 4700;
        raw.flags = dns_flags::NSS;
        raw.timestamp_ns = 7_000;
        let name = b"foo.northnarrow-e2etest.invalid.";
        raw.query_name[..name.len()].copy_from_slice(name);
        raw.qname_len = name.len() as u16;
        assert!(nss_events(&raw, &lineage, Some(&cache)).is_none());
        assert_eq!(
            cache.lookup_for_connect(4700, 8_000, 0).as_deref(),
            Some("foo.northnarrow-e2etest.invalid")
        );
        assert_eq!(
            cache.originator_for("foo.northnarrow-e2etest.invalid", 8_000, 2_000_000_000, 1),
            None,
            "not a query to a local stub"
        );
        raw.held = 5;
        raw.flags |= dns_flags::RATE_HELD;
        assert!(matches!(
            nss_events(&raw, &lineage, Some(&cache)),
            Some(Event::DnsFlood {
                pid: 4700,
                held: 5,
                ..
            })
        ));
        // an empty name feeds nothing
        let mut empty = DnsQueryRaw::zeroed();
        empty.pid = 4701;
        empty.flags = dns_flags::NSS;
        assert!(nss_events(&empty, &lineage, Some(&cache)).is_none());
        assert_eq!(cache.lookup_for_connect(4701, 8_000, 0), None);
    }

    /// External audit SNS-015: every event ring of the eBPF object is
    /// process-local, `FS_PROTECT_EVENTS` included (it was pinned and
    /// reused before the BUG-024 fix, and comments here still said so).
    #[test]
    fn no_event_ring_is_pinned() {
        let src = std::path::Path::new(env!("NN_REPO_ROOT")).join("agent-ebpf/src");
        let mut rings = Vec::new();
        for entry in std::fs::read_dir(&src).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(
                !text.contains("RingBuf::pinned"),
                "{}: a pinned ring buffer",
                path.display()
            );
            for line in text.lines().map(str::trim) {
                if line.starts_with("//") || !line.contains(": RingBuf =") {
                    continue;
                }
                assert!(
                    line.contains("RingBuf::with_byte_size("),
                    "{}: {line}",
                    path.display()
                );
                let name = line
                    .split(": RingBuf")
                    .next()
                    .and_then(|l| l.split_whitespace().last())
                    .unwrap_or_default();
                rings.push(name.to_string());
            }
        }
        for ring in [
            "FS_PROTECT_EVENTS",
            "OPEN_SENSOR_EVENTS",
            "DNS_QUERY_EVENTS",
            "EVENTS",
        ] {
            assert!(
                rings.iter().any(|r| r == ring),
                "{ring} not found in {rings:?}"
            );
        }
        assert!(rings.iter().all(|r| r.ends_with("EVENTS")), "{rings:?}");
    }

    /// Lot 269 (R12b-1): the denials' ring is loaded at four times the
    /// size the object declares, a power of two of whole pages (a ring
    /// buffer's size must be), under the object's own name for it.
    #[test]
    fn the_denials_ring_is_loaded_four_times_the_object_s() {
        let src =
            std::path::Path::new(env!("NN_REPO_ROOT")).join("agent-ebpf/src/inode_protect.rs");
        let text = std::fs::read_to_string(&src).unwrap();
        let line = text
            .lines()
            .map(str::trim)
            .find(|l| !l.starts_with("//") && l.contains(&format!("{FS_PROTECT_RING}: RingBuf =")))
            .expect("the object's declaration of the denials' ring");
        let size = line
            .split("with_byte_size(")
            .nth(1)
            .and_then(|r| r.split(',').next())
            .expect("its byte size");
        let declared: u32 = size
            .split('*')
            .map(|f| f.trim().parse::<u32>().expect("a product of integers"))
            .product();
        assert_eq!(declared, 64 * 1024, "{line}");
        assert!(FS_PROTECT_RING_BYTES >= 4 * declared);
        assert!(FS_PROTECT_RING_BYTES.is_power_of_two());
        assert_eq!(FS_PROTECT_RING_BYTES % 4096, 0);
        let record = (std::mem::size_of::<FsProtectDenialRaw>() + 8) as u32;
        assert_eq!(FS_PROTECT_RING_BYTES / record, 4096);
    }

    /// Lot 269 (R12b-1): the loader is given that size before it loads the
    /// object, and the pump reads the ring by that name — read from the
    /// production code, before this file's tests.
    #[test]
    fn the_loader_sizes_the_denials_ring_before_the_load() {
        let text = include_str!("multiplexer.rs");
        let code = &text[..text.find("#[cfg(test)]").expect("the tests")];
        let sized = code
            .find("loader.map_max_entries(FS_PROTECT_RING, FS_PROTECT_RING_BYTES);")
            .expect("the loader sizes the denials' ring");
        let loaded = code.find(".load(EBPF_BYTES)").expect("the load");
        assert!(sized < loaded, "sized after the load");
        assert_eq!(code.matches(".load(EBPF_BYTES)").count(), 1);
        assert!(code.contains("take_ringbuf(&mut ebpf, FS_PROTECT_RING)?"));
    }

    /// External audit SNS-012 (NN-AUD-355): the WARN for an unarmed
    /// `BTF_OFFSETS` says what the start does next, not only that the
    /// compiled-in offsets apply.
    #[test]
    fn the_unarmed_btf_warning_says_what_the_start_does() {
        let agent = btf_offsets_unarmed_warning(false, true);
        assert!(agent.contains("no vmlinux BTF") && agent.contains("start fails"));
        assert!(agent.contains("tcp_close fexit"));
        let no_net = btf_offsets_unarmed_warning(false, false);
        assert!(no_net.contains("attach_anti_tamper refuses"));
        assert!(no_net.contains("NN_ANTI_TAMPER_ALLOW_DEGRADED=1"));
        for net in [true, false] {
            let w = btf_offsets_unarmed_warning(true, net);
            assert!(w.contains("exists") && w.contains("compiled-in offsets"));
            assert!(!w.contains("start fails"));
        }
        for w in [agent, no_net] {
            assert!(w.starts_with("BTF_OFFSETS map NOT armed"));
        }
    }
}
