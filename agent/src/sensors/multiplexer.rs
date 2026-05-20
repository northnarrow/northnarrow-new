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
    include_bytes_aligned,
    maps::{ring_buf::RingBuf, MapData},
    programs::{FExit, KProbe, TracePoint},
    Btf, Ebpf, EbpfLoader,
};
use bytemuck::Pod;
use common::wire::{
    DnsQueryRaw, ExecCheckRaw, FileOpenRaw, FsProtectDenialRaw, ProcessSpawnRaw, TcpConnectRaw,
};
use common::Event;
use parking_lot::Mutex;
use tokio::{io::unix::AsyncFd, sync::mpsc, task::JoinHandle};
use tracing::{debug, error, info, warn};

use crate::net::dns_cache::DnsCache;
use crate::net::flow_tracker::{FlowTracker, TcpConnectInfo};

/// eBPF object embedded by `agent/build.rs`; same alignment trick as
/// in the Tappa 1 sensor.
static EBPF_BYTES: &[u8] =
    include_bytes_aligned!(concat!(env!("OUT_DIR"), "/northnarrow-agent-ebpf"));

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
}

/// Owns the loaded eBPF object and every attached link. Dropping the
/// multiplexer detaches everything and aborts the pump tasks.
pub struct SensorMultiplexer {
    ebpf: Ebpf,
    pumps: Vec<JoinHandle<()>>,
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

        // Tappa 7 task 6 commit #2: pin the six anti-tamper maps
        // by-name to bpffs so a restarted agent reuses the SAME
        // kernel map objects the pinned LSM hooks reference (closes
        // the split-brain regression). `prepare_pin_root` returns
        // `None` on a host without bpffs; we then load unpinned so
        // sensors still run. Only maps declared `#[map]` with a
        // `::pinned(..)` constructor are affected — the five sensor
        // ringbufs stay process-local by design.
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

        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            debug!(?e, "aya-log not initialised (no logger map exported)");
        }

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
        attach_tracepoint(
            &mut ebpf,
            "sys_enter_execve",
            "syscalls",
            "sys_enter_execve",
        )?;
        attach_kprobe(&mut ebpf, "tcp_v4_connect", "tcp_v4_connect")?;
        attach_kprobe(&mut ebpf, "tcp_v6_connect", "tcp_v6_connect")?;
        attach_kprobe(&mut ebpf, "udp_sendmsg", "udp_sendmsg")?;

        // Tappa 10 N9 — attach the three N2 network programs only
        // when the caller passed `NetWiring`. Without a drain task
        // the close + listen ringbufs would fill up + drop events,
        // and the kernel-side observation would waste cycles. Keep
        // start() lean for the existing exec_sensor_live test.
        let net_bufs = if net.is_some() {
            // `tcp_close` is fexit — needs vmlinux BTF for the
            // function signature. The dev kernel (6.8.x) ships
            // BTF unconditionally; the load is degrade-not-fail.
            let btf =
                Btf::from_sys_fs().with_context(|| "loading vmlinux BTF for net fexit programs")?;
            attach_kprobe(&mut ebpf, "inet_csk_listen_start", "inet_csk_listen_start")?;
            attach_fexit(&mut ebpf, "tcp_close", &btf)?;
            attach_kprobe(&mut ebpf, "udp_sendmsg_outbound", "udp_sendmsg")?;
            let close_rb = take_ringbuf(&mut ebpf, "NET_FLOW_CLOSE_EVENTS")?;
            let listen_rb = take_ringbuf(&mut ebpf, "NET_LISTEN_EVENTS")?;
            info!("net: N2 BPF programs attached (inet_csk_listen_start kprobe + tcp_close fexit + udp_sendmsg_outbound kprobe)");
            Some(NetRingBufs {
                close_rb,
                listen_rb,
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

        let (tx, rx) = mpsc::channel::<Event>(CHANNEL_CAPACITY);
        let flow_tracker_for_tcp = net.as_ref().map(|w| Arc::clone(&w.flow_tracker));
        let dns_cache_for_dns = net.as_ref().map(|w| Arc::clone(&w.dns_cache));

        let pumps = vec![
            spawn_pump::<ProcessSpawnRaw>("process_spawn", process_spawn_rb, tx.clone()),
            spawn_pump::<FileOpenRaw>("file_open", file_open_rb, tx.clone()),
            spawn_pump::<ExecCheckRaw>("exec_check", exec_check_rb, tx.clone()),
            spawn_tcp_connect_pump(tcp_connect_rb, flow_tracker_for_tcp, tx.clone()),
            spawn_dns_query_pump(dns_query_rb, dns_cache_for_dns, tx.clone()),
            spawn_pump::<FsProtectDenialRaw>("fs_protect", fs_protect_rb, tx.clone()),
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

    /// Tappa 9 C8 — register the spawned FIM drain task with the
    /// multiplexer so `Drop` aborts it alongside the sensor pumps.
    pub fn register_pump_handle(&mut self, handle: JoinHandle<()>) {
        self.pumps.push(handle);
    }

    /// Drain the next event. Returns `None` when every pump task has
    /// exited (which only happens at shutdown).
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
        allowed_comms: &std::collections::HashSet<String>,
    ) -> Result<()> {
        crate::anti_tamper::attach(&mut self.ebpf, pids, allowed_comms)
    }
}

impl Drop for SensorMultiplexer {
    fn drop(&mut self) {
        for h in self.pumps.drain(..) {
            h.abort();
        }
    }
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
        .with_context(|| format!("attaching tracepoint {category}/{name}"))?;
    Ok(())
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
        .with_context(|| format!("attaching kprobe to {symbol}"))?;
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
    let mut async_fd = AsyncFd::new(rb)?;
    loop {
        let mut guard = async_fd.readable_mut().await?;
        let inner = guard.get_inner_mut();
        let mut drained = 0u32;
        while let Some(item) = inner.next() {
            drained += 1;
            let bytes: &[u8] = item.as_ref();
            match bytemuck::try_from_bytes::<T>(bytes) {
                Ok(raw) => {
                    if tx.send(Event::from(raw)).await.is_err() {
                        return Ok(());
                    }
                }
                Err(e) => warn!(
                    label,
                    expected = std::mem::size_of::<T>(),
                    got = bytes.len(),
                    error = %e,
                    "ringbuf entry rejected"
                ),
            }
        }
        guard.clear_ready();
        if drained == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    }
}

// ── Tappa 10 N9 — feeder-aware TcpConnect + DnsQuery pumps ───────────

fn spawn_tcp_connect_pump(
    rb: RingBuf<MapData>,
    flow_tracker: Option<Arc<Mutex<FlowTracker>>>,
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
    flow_tracker: Option<Arc<Mutex<FlowTracker>>>,
    tx: mpsc::Sender<Event>,
) -> std::io::Result<()> {
    let mut async_fd = AsyncFd::new(rb)?;
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
                    if let Some(ft) = flow_tracker.as_ref() {
                        let info = tcp_connect_info_from_raw(raw);
                        ft.lock().on_tcp_connect(&info);
                    }
                    if tx.send(Event::from(raw)).await.is_err() {
                        return Ok(());
                    }
                }
                Err(e) => warn!(
                    expected = std::mem::size_of::<TcpConnectRaw>(),
                    got = bytes.len(),
                    error = %e,
                    "tcp_connect ringbuf entry rejected"
                ),
            }
        }
        guard.clear_ready();
        if drained == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    }
}

fn tcp_connect_info_from_raw(raw: &TcpConnectRaw) -> TcpConnectInfo {
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
        // `exe` resolution via /proc is a hot-path cost we skip
        // here — N3 design says exe is best-effort; the field
        // stays None until the future exe-resolver hook (N3.1
        // or admin-CLI lazy lookup).
        exe: None,
    }
}

fn decode_addr(family: u8, bytes: [u8; 16]) -> std::net::IpAddr {
    if family == 2 {
        let mut v4 = [0u8; 4];
        v4.copy_from_slice(&bytes[..4]);
        std::net::IpAddr::V4(std::net::Ipv4Addr::from(v4))
    } else {
        std::net::IpAddr::V6(std::net::Ipv6Addr::from(bytes))
    }
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
    loop {
        let mut guard = async_fd.readable_mut().await?;
        let inner = guard.get_inner_mut();
        let mut drained = 0u32;
        while let Some(item) = inner.next() {
            drained += 1;
            let bytes: &[u8] = item.as_ref();
            match bytemuck::try_from_bytes::<DnsQueryRaw>(bytes) {
                Ok(raw) => {
                    let event = Event::from(raw);
                    if let (
                        Some(cache),
                        Event::DnsQuery {
                            pid,
                            query_name,
                            query_type,
                            timestamp_ns,
                            ..
                        },
                    ) = (dns_cache.as_ref(), &event)
                    {
                        cache.on_dns_query(*pid, query_name.clone(), *query_type, *timestamp_ns);
                    }
                    if tx.send(event).await.is_err() {
                        return Ok(());
                    }
                }
                Err(e) => warn!(
                    expected = std::mem::size_of::<DnsQueryRaw>(),
                    got = bytes.len(),
                    error = %e,
                    "dns_query ringbuf entry rejected"
                ),
            }
        }
        guard.clear_ready();
        if drained == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    }
}
