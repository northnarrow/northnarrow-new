//! Process-exec sensor (Tappa 1).
//!
//! Loads the compiled eBPF program (`agent-ebpf/`), attaches it to the
//! `sched/sched_process_exec` tracepoint, opens the
//! `EVENTS` ringbuffer, and forwards every event as a typed
//! [`common::Event::ProcessSpawn`] over a tokio mpsc channel.
//!
//! The eBPF object is embedded via the build script: see
//! `agent/build.rs`.

use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use aya::{include_bytes_aligned, maps::ring_buf::RingBuf, programs::TracePoint, Ebpf, EbpfLoader};
use common::{wire::ProcessSpawnRaw, Event};
use tokio::{io::unix::AsyncFd, sync::mpsc, task::JoinHandle};
use tracing::{debug, error, warn};

/// Compiled eBPF object, staged into OUT_DIR by `build.rs`.
///
/// `include_bytes_aligned!` wraps the bytes in a `#[repr(align(32))]`
/// struct: aya's ELF parser does pointer-aligned reads internally and
/// fails with "error parsing ELF data" if it gets a 1-byte-aligned
/// slice (which is what `core::include_bytes!` produces).
static EBPF_BYTES: &[u8] =
    include_bytes_aligned!(concat!(env!("OUT_DIR"), "/northnarrow-agent-ebpf"));

/// Ringbuffer map name (must match `agent-ebpf/src/main.rs`).
const RINGBUF_NAME: &str = "EVENTS";

/// Tracepoint category and name we attach to.
const TP_CATEGORY: &str = "sched";
const TP_NAME: &str = "sched_process_exec";

/// Backing eBPF program owned by the running sensor. Dropping it
/// detaches the tracepoint and releases all maps.
pub struct ExecSensor {
    _ebpf: Ebpf,
    pump: JoinHandle<()>,
    rx: mpsc::Receiver<Event>,
}

impl ExecSensor {
    /// Channel capacity between the kernel ringbuf pump and the
    /// agent's main loop. Bursty exec storms can fill this; the pump
    /// applies backpressure by simply not draining the ringbuf.
    pub const CHANNEL_CAPACITY: usize = 1024;

    /// Load the eBPF object, attach the tracepoint, start the pump.
    pub async fn start() -> Result<Self> {
        if EBPF_BYTES.is_empty() {
            bail!(
                "eBPF program not built: agent/build.rs found no artifact. Run \
                 `cargo xtask build-ebpf` first."
            );
        }

        // Pass `btf(None)` explicitly: bpf-linker 0.10 does not emit a
        // `.BTF` section for Rust-built objects, and aya's default of
        // pulling /sys/kernel/btf/vmlinux is fine for kernel-side
        // verification but must be allowed to be absent on the program
        // itself, otherwise loading fails with "error parsing ELF data".
        let mut ebpf = EbpfLoader::new()
            .btf(None)
            .load(EBPF_BYTES)
            .with_context(|| "loading eBPF object (BTF, maps, programs)")?;

        // Try to wire up aya-log; it's a no-op if the eBPF program
        // doesn't ship a logger map, so any error is non-fatal.
        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            debug!(?e, "aya-log not initialised (no logger map exported)");
        }

        let program: &mut TracePoint = ebpf
            .program_mut(TP_NAME)
            .ok_or_else(|| anyhow!("eBPF program `{TP_NAME}` not found in loaded object"))?
            .try_into()
            .with_context(|| format!("program `{TP_NAME}` is not a tracepoint"))?;
        program
            .load()
            .with_context(|| format!("verifier rejected `{TP_NAME}`"))?;
        program
            .attach(TP_CATEGORY, TP_NAME)
            .with_context(|| format!("attaching {TP_CATEGORY}/{TP_NAME}"))?;

        let map = ebpf
            .take_map(RINGBUF_NAME)
            .ok_or_else(|| anyhow!("ringbuf map `{RINGBUF_NAME}` missing from eBPF object"))?;
        let ringbuf = RingBuf::try_from(map)
            .map_err(|e| anyhow!("expected `{RINGBUF_NAME}` to be a RINGBUF: {e}"))?;

        let (tx, rx) = mpsc::channel(Self::CHANNEL_CAPACITY);
        let pump = tokio::spawn(pump_ringbuf(ringbuf, tx));

        Ok(Self {
            _ebpf: ebpf,
            pump,
            rx,
        })
    }

    /// Receive the next event, or `None` when the pump exits.
    pub async fn next_event(&mut self) -> Option<Event> {
        self.rx.recv().await
    }
}

impl Drop for ExecSensor {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

/// Background task: blocks on the ringbuf fd, drains it as data
/// arrives, decodes each entry as [`ProcessSpawnRaw`], and forwards
/// the typed [`Event`] to userland.
async fn pump_ringbuf(ringbuf: RingBuf<aya::maps::MapData>, tx: mpsc::Sender<Event>) {
    let mut async_fd = match AsyncFd::new(ringbuf) {
        Ok(fd) => fd,
        Err(e) => {
            error!(error = %e, "failed to register ringbuf fd with tokio");
            return;
        }
    };

    loop {
        // Wait until the kernel says the ringbuf has data.
        let mut guard = match async_fd.readable_mut().await {
            Ok(g) => g,
            Err(e) => {
                error!(error = %e, "ringbuf fd read-readiness wait failed");
                return;
            }
        };

        let rb = guard.get_inner_mut();
        let mut drained = 0u32;
        while let Some(item) = rb.next() {
            drained += 1;
            match decode_event(item.as_ref()) {
                Ok(ev) => {
                    if tx.send(ev).await.is_err() {
                        // Receiver dropped — we're shutting down.
                        return;
                    }
                }
                Err(e) => warn!(error = %e, "ringbuf entry rejected"),
            }
        }

        // Mark not-ready so the next `readable_mut().await` blocks
        // again until new data arrives.
        guard.clear_ready();

        if drained == 0 {
            // Defensive: should not happen with edge-triggered fds,
            // but yield briefly so we don't spin if it does.
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
}

/// Decode one ringbuf record into a typed event.
fn decode_event(buf: &[u8]) -> Result<Event> {
    let raw: &ProcessSpawnRaw = bytemuck::try_from_bytes(buf).map_err(|e| {
        anyhow!(
            "ringbuf entry size {} not a valid ProcessSpawnRaw ({} bytes): {e}",
            buf.len(),
            std::mem::size_of::<ProcessSpawnRaw>()
        )
    })?;
    Ok(Event::from(raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::wire::{ProcessSpawnRaw, FILENAME_LEN, TASK_COMM_LEN};

    fn make_raw(pid: u32, comm: &str, filename: &str) -> ProcessSpawnRaw {
        let mut raw = ProcessSpawnRaw::zeroed();
        raw.pid = pid;
        raw.ppid = 1;
        raw.uid = 1000;
        raw.gid = 1000;
        raw.timestamp_ns = 42;
        let cb = comm.as_bytes();
        let n = cb.len().min(TASK_COMM_LEN);
        raw.comm[..n].copy_from_slice(&cb[..n]);
        let fb = filename.as_bytes();
        let n = fb.len().min(FILENAME_LEN);
        raw.filename[..n].copy_from_slice(&fb[..n]);
        raw
    }

    #[test]
    fn decode_event_parses_a_pod_buffer() {
        let raw = make_raw(4242, "ls", "/usr/bin/ls");
        let buf: &[u8] = bytemuck::bytes_of(&raw);
        let evt = decode_event(buf).expect("decode");
        match evt {
            Event::ProcessSpawn {
                pid,
                comm,
                filename,
                ..
            } => {
                assert_eq!(pid, 4242);
                assert_eq!(comm, "ls");
                assert_eq!(filename, "/usr/bin/ls");
            }
            _ => panic!("expected ProcessSpawn"),
        }
    }

    #[test]
    fn decode_event_surfaces_d2_parent_context_and_argv() {
        // Simulate what the Tappa 10.6 D2 BPF refit writes: populated
        // ppid (parent tgid), parent_comm, parent_start_ns, and a
        // NUL-separated argv blob. Locks the agent-side decode contract.
        let mut raw = make_raw(4242, "ls", "/bin/ls");
        raw.ppid = 1000;
        raw.parent_start_ns = 123_000;
        let pc = b"bash";
        raw.parent_comm[..pc.len()].copy_from_slice(pc);
        let argv = b"ls\0-la\0/tmp\0";
        raw.argv[..argv.len()].copy_from_slice(argv);
        raw.argv_len = argv.len() as u16;

        let buf: &[u8] = bytemuck::bytes_of(&raw);
        let evt = decode_event(buf).expect("decode");
        match evt {
            Event::ProcessSpawn {
                ppid,
                argv,
                parent_comm,
                parent_start_ns,
                ..
            } => {
                assert_eq!(ppid, 1000);
                assert_eq!(parent_comm, "bash");
                assert_eq!(parent_start_ns, 123_000);
                assert_eq!(argv, vec!["ls", "-la", "/tmp"]);
            }
            _ => panic!("expected ProcessSpawn"),
        }
    }

    #[test]
    fn decode_event_rejects_wrong_size() {
        let too_short = [0u8; 8];
        assert!(decode_event(&too_short).is_err());
    }
}
