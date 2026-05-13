//! Single-owner eBPF object loader + per-ringbuf pump tasks.
//!
//! Loads the compiled eBPF object once, attaches all six programs
//! (one tracepoint exec + two syscall tracepoints + three kprobes),
//! drains each program's dedicated ringbuf, and funnels every decoded
//! event into a unified [`mpsc`] channel. The agent main loop reads
//! from a single `Receiver<Event>` and stays oblivious to which
//! sensor produced what.

use anyhow::{anyhow, Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{ring_buf::RingBuf, MapData},
    programs::{KProbe, TracePoint},
    Ebpf, EbpfLoader,
};
use bytemuck::Pod;
use common::wire::{
    DnsQueryRaw, ExecCheckRaw, FileOpenRaw, FsProtectDenialRaw, ProcessSpawnRaw, TcpConnectRaw,
};
use common::Event;
use tokio::{io::unix::AsyncFd, sync::mpsc, task::JoinHandle};
use tracing::{debug, error, warn};

/// eBPF object embedded by `agent/build.rs`; same alignment trick as
/// in the Tappa 1 sensor.
static EBPF_BYTES: &[u8] =
    include_bytes_aligned!(concat!(env!("OUT_DIR"), "/northnarrow-agent-ebpf"));

/// Channel between the per-ringbuf pumps and the agent main loop.
const CHANNEL_CAPACITY: usize = 4096;

/// Owns the loaded eBPF object and every attached link. Dropping the
/// multiplexer detaches everything and aborts the pump tasks.
pub struct SensorMultiplexer {
    ebpf: Ebpf,
    pumps: Vec<JoinHandle<()>>,
    rx: mpsc::Receiver<Event>,
    /// Anti-tamper handle. Created during `start()` (same place as
    /// the loader configuration) so the bpffs root and map_pin_path
    /// agree by construction. Threaded through `attach_anti_tamper`
    /// at boot; the watchdog will also clone it (commit #3) for the
    /// SIGCHLD `evict_pid` path.
    antitamper: antitamper_bpf::AntiTamper,
}

impl SensorMultiplexer {
    /// Load + attach + start. The returned multiplexer is hot: events
    /// will already be flowing into the channel by the time it
    /// returns.
    pub async fn start() -> Result<Self> {
        if EBPF_BYTES.is_empty() {
            anyhow::bail!(
                "eBPF program not built: agent/build.rs found no artifact. Run \
                 `cargo xtask build-ebpf` first."
            );
        }

        // Tappa 7 task 6 commit #2: tell aya to pin every map in
        // the object to `/sys/fs/bpf/northnarrow/<MAP_NAME>` AND to
        // auto-reuse any pin that already exists. This is the
        // built-in load-or-create path; no manual map-pin code on
        // our side. The bpffs root is created by `AntiTamper::new`
        // if missing, so the parent directory always exists when
        // aya goes to write the pin file.
        let antitamper = antitamper_bpf::AntiTamper::new(antitamper_bpf::DEFAULT_BPFFS_ROOT.into())
            .with_context(|| {
                format!(
                    "preparing bpffs root {}",
                    antitamper_bpf::DEFAULT_BPFFS_ROOT
                )
            })?;
        let mut loader = EbpfLoader::new();
        loader.btf(None);
        antitamper.configure_loader(&mut loader);
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

        let process_spawn_rb = take_ringbuf(&mut ebpf, "EVENTS")?;
        let file_open_rb = take_ringbuf(&mut ebpf, "FILE_OPEN_EVENTS")?;
        let exec_check_rb = take_ringbuf(&mut ebpf, "EXEC_CHECK_EVENTS")?;
        let tcp_connect_rb = take_ringbuf(&mut ebpf, "TCP_CONNECT_EVENTS")?;
        let dns_query_rb = take_ringbuf(&mut ebpf, "DNS_QUERY_EVENTS")?;
        let fs_protect_rb = take_ringbuf(&mut ebpf, "FS_PROTECT_EVENTS")?;

        let (tx, rx) = mpsc::channel::<Event>(CHANNEL_CAPACITY);
        let pumps = vec![
            spawn_pump::<ProcessSpawnRaw>("process_spawn", process_spawn_rb, tx.clone()),
            spawn_pump::<FileOpenRaw>("file_open", file_open_rb, tx.clone()),
            spawn_pump::<ExecCheckRaw>("exec_check", exec_check_rb, tx.clone()),
            spawn_pump::<TcpConnectRaw>("tcp_connect", tcp_connect_rb, tx.clone()),
            spawn_pump::<DnsQueryRaw>("dns_query", dns_query_rb, tx.clone()),
            spawn_pump::<FsProtectDenialRaw>("fs_protect", fs_protect_rb, tx),
        ];

        Ok(Self {
            ebpf,
            pumps,
            rx,
            antitamper,
        })
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
        crate::anti_tamper::attach(&mut self.ebpf, &self.antitamper, pids, allowed_comms)
    }

    /// Borrow the anti-tamper handle so external callers (e.g. the
    /// future watchdog crate in commit #3) can issue the
    /// SIGCHLD-side `evict_pid` against the same bpffs root.
    pub fn antitamper(&self) -> &antitamper_bpf::AntiTamper {
        &self.antitamper
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
