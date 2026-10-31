//! The ring pumps on threads of their own (Wave 4 restructure, R12b, lab
//! PR 269; plan §3.4).
//!
//! Until R12b every pump was a task of the agent's async runtime: woken by
//! the runtime's reactor, run when a worker had time, sending one event at
//! a time — each send a round of the bus's locks and semaphores. On a guest
//! whose CPUs a flood saturates (EXP-13c, EXP-13e) a ring fell behind while
//! no send of the bus had waited for room: in EXP-13e, a root loop of new
//! processes' refused `chmod`s, the tip of R12a lost more `fs_protect`
//! records than `main` in three runs each (`EVENT_BUS.md` §7).
//!
//! A pump here is an OS thread that blocks in `poll(2)` on its ring's
//! descriptor — the kernel wakes it, no runtime in between — reads what the
//! ring holds and sends it in batches ([`BusSender::send_batch_blocking`]):
//! at most [`BATCH_MAX`] events per round of the bus's lock, sent as soon
//! as the ring is read empty or the batch is full — never held back to fill
//! one. A wait for room, the rare case, runs on the runtime's timers while
//! the thread blocks, as the task waited before.
//!
//! What stays as it was: a pump never ends while the agent runs, so one that
//! ended — returned, failed, panicked — is a blind spot the event loop finds
//! (external audit SNS-001: [`Pump::is_finished`]) and the agent stops; a
//! closed bus ends it (the agent is stopping); a record shorter than its
//! type is counted and WARNed ([`RejectThrottle`]).

use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;
use tracing::error;

use crate::sensors::bus::{BusSender, SendError, BATCH_MAX};
use crate::sensors::reject::RejectThrottle;

/// How long a pump's `poll(2)` waits before it looks at its stop flag: the
/// most a stopped pump (the multiplexer dropped, a lab build's abort) runs
/// on.
pub const POLL_MS: i32 = 250;

/// The most records a pump reads in one pass before it sends what it has:
/// a ring a producer keeps filling does not hold a pass forever.
pub const PASS_MAX: usize = 4 * BATCH_MAX;

/// A pump on a thread of its own: its handle and its stop flag.
pub struct PumpThread {
    handle: std::thread::JoinHandle<()>,
    stop: Arc<AtomicBool>,
}

impl PumpThread {
    /// Start `body` on a thread named after `label` (`nn-` and the label,
    /// cut to the kernel's 15 bytes). `body` gets the stop flag, which it
    /// reads at least every [`POLL_MS`]; an error it returns is logged, a
    /// panic ends the thread — either way the thread is finished, which
    /// [`Pump::is_finished`] reports.
    pub fn spawn(
        label: &'static str,
        body: impl FnOnce(&AtomicBool) -> io::Result<()> + Send + 'static,
    ) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let name: String = format!("nn-{label}").chars().take(15).collect();
        let handle = std::thread::Builder::new().name(name).spawn(move || {
            if let Err(e) = body(&flag) {
                error!(label, error = %e, "ringbuf pump failed");
            }
        })?;
        Ok(Self { handle, stop })
    }

    /// Ask the pump to end (it does within [`POLL_MS`]).
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
    }

    /// The thread has ended.
    pub fn is_finished(&self) -> bool {
        self.handle.is_finished()
    }
}

/// A telemetry task the multiplexer keeps (external audit SNS-001): a pump
/// on a thread of its own (R12b), or a task of the runtime (the FIM and
/// network drains, the open sensor's rule refresher, the loss recorder).
pub enum Pump {
    Task(JoinHandle<()>),
    Thread(PumpThread),
}

impl Pump {
    /// It has ended: a blind spot.
    pub fn is_finished(&self) -> bool {
        match self {
            Pump::Task(h) => h.is_finished(),
            Pump::Thread(t) => t.is_finished(),
        }
    }

    /// End it: a task is aborted, a thread asked to stop.
    pub fn stop(&self) {
        match self {
            Pump::Task(h) => h.abort(),
            Pump::Thread(t) => t.stop(),
        }
    }
}

/// A ring a pump reads: its records, one at a time, and a wait for more.
pub trait RingSource {
    /// Hand the next record's bytes to `f`; `false` when the ring is empty.
    fn next_record(&mut self, f: &mut dyn FnMut(&[u8])) -> bool;

    /// Block until the ring has a record or `timeout_ms` passed.
    fn wait(&mut self, timeout_ms: i32) -> io::Result<()>;
}

impl<T: std::borrow::Borrow<aya::maps::MapData>> RingSource for aya::maps::RingBuf<T> {
    fn next_record(&mut self, f: &mut dyn FnMut(&[u8])) -> bool {
        match self.next() {
            Some(item) => {
                f(&item);
                true
            }
            None => false,
        }
    }

    fn wait(&mut self, timeout_ms: i32) -> io::Result<()> {
        wait_readable(self.as_raw_fd(), timeout_ms)
    }
}

/// `poll(2)` for `fd` readable, at most `timeout_ms`; an interrupted wait
/// is a wait that ended.
pub fn wait_readable(fd: RawFd, timeout_ms: i32) -> io::Result<()> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd for the duration of the call; `fd` is the
    // ring's, open for as long as its owner (the caller) lives.
    let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if rc < 0 {
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
    Ok(())
}

/// One pass's events: the records read, each made into its events by
/// `decode` (`None`: a record too short for its type, counted).
pub type Decode<'a> = dyn FnMut(&[u8], &mut Vec<nn_model::Event>) -> bool + 'a;

/// The pump's loop: read the ring, at most [`PASS_MAX`] records a pass,
/// sending each [`BATCH_MAX`] events and what is left when the ring is
/// read empty; then wait for the next record. `decode` turns a record's
/// bytes into its events (pushed in the bus's order) and says whether it
/// could; `label` and `record_size` name the ring for the rejected
/// records' count. Returns when the stop flag is set (`Ok`) or the bus is
/// closed (`Ok`: the agent stops), or the wait fails (`Err`).
pub fn run_ring(
    label: &'static str,
    record_size: usize,
    ring: &mut dyn RingSource,
    tx: &BusSender,
    rt: &tokio::runtime::Handle,
    stop: &AtomicBool,
    decode: &mut Decode<'_>,
) -> io::Result<()> {
    let mut reject = RejectThrottle::new();
    let mut batch: Vec<nn_model::Event> = Vec::with_capacity(BATCH_MAX + 4);
    loop {
        if stop.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut read = 0usize;
        let mut rejected = false;
        while read < PASS_MAX {
            let mut bad: Option<usize> = None;
            let got = ring.next_record(&mut |bytes| {
                if !decode(bytes, &mut batch) {
                    bad = Some(bytes.len());
                }
            });
            if !got {
                break;
            }
            read += 1;
            if let Some(len) = bad {
                reject.record(label, record_size, len);
                rejected = true;
            }
            if batch.len() >= BATCH_MAX && send(tx, rt, &mut batch).is_err() {
                return Ok(());
            }
        }
        if !batch.is_empty() && send(tx, rt, &mut batch).is_err() {
            return Ok(());
        }
        if read < PASS_MAX {
            // read empty: wait for the next record
            if !rejected {
                reject.flush_idle(label, record_size);
            }
            ring.wait(POLL_MS)?;
        }
    }
}

/// Send the batch and empty it.
fn send(
    tx: &BusSender,
    rt: &tokio::runtime::Handle,
    batch: &mut Vec<nn_model::Event>,
) -> Result<(), SendError> {
    tx.send_batch_blocking(rt, std::mem::take(batch))
}

/// The time a stopped pump may still run: tests wait this long.
pub const STOP_WITHIN: Duration = Duration::from_millis(POLL_MS as u64 * 2);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sensors::bus::channel;
    use nn_model::Event;
    use std::collections::VecDeque;

    /// A ring of records in memory; `wait` returns at once (counting) and,
    /// after `stop_after` waits, sets the stop flag it is given.
    struct FakeRing {
        records: VecDeque<Vec<u8>>,
        waits: usize,
        stop_after: usize,
        stop: Arc<AtomicBool>,
        /// Records to add at each wait (a producer behind the pump).
        later: VecDeque<Vec<Vec<u8>>>,
    }

    impl RingSource for FakeRing {
        fn next_record(&mut self, f: &mut dyn FnMut(&[u8])) -> bool {
            match self.records.pop_front() {
                Some(r) => {
                    f(&r);
                    true
                }
                None => false,
            }
        }
        fn wait(&mut self, _timeout_ms: i32) -> io::Result<()> {
            self.waits += 1;
            if let Some(more) = self.later.pop_front() {
                self.records.extend(more);
            }
            if self.waits >= self.stop_after {
                self.stop.store(true, Ordering::Release);
            }
            Ok(())
        }
    }

    fn denial(pid: u32, ts: u64) -> Event {
        Event::FsProtectDenial {
            pid,
            uid: pid,
            comm: "chmod".into(),
            target_dev: 1,
            target_ino: u64::from(pid),
            operation: nn_model::FsProtectOperation::Setattr,
            timestamp_ns: ts,
        }
    }

    /// A record: 4 bytes of pid, or 1 byte for a short one.
    fn rec(pid: u32) -> Vec<u8> {
        pid.to_le_bytes().to_vec()
    }

    fn decode_pid(bytes: &[u8], out: &mut Vec<Event>) -> bool {
        let Ok(b) = <[u8; 4]>::try_from(bytes) else {
            return false;
        };
        out.push(denial(u32::from_le_bytes(b), 1));
        true
    }

    /// R12b: the pump reads the ring in passes, sends in batches of at most
    /// [`BATCH_MAX`], every record once and in its order, a short record
    /// counted and skipped; it waits once the ring is read empty, reads what
    /// came meanwhile, and ends on its stop flag.
    #[test]
    fn the_pump_sends_the_ring_in_order_in_bounded_batches() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (tx, mut rx) = channel();
        let tx = tx.for_source("test");
        let stop = Arc::new(AtomicBool::new(false));
        let n = (BATCH_MAX * 2 + 7) as u32;
        let mut records: VecDeque<Vec<u8>> = (0..n).map(rec).collect();
        records.insert(5, vec![0u8]);
        let mut ring = FakeRing {
            records,
            waits: 0,
            stop_after: 2,
            stop: Arc::clone(&stop),
            later: VecDeque::from([vec![rec(n), rec(n + 1)]]),
        };
        let mut decode = decode_pid;
        run_ring("test", 4, &mut ring, &tx, rt.handle(), &stop, &mut decode).unwrap();
        assert_eq!(
            ring.waits, 2,
            "a wait after each pass that read the ring empty"
        );
        let pids: Vec<u32> = std::iter::from_fn(|| rx.try_recv())
            .map(|r| match r.envelope.event {
                Event::FsProtectDenial { pid, .. } => pid,
                e => panic!("{e:?}"),
            })
            .collect();
        assert_eq!(
            pids,
            (0..n + 2).collect::<Vec<_>>(),
            "every record once, in order"
        );
        let rejected: u64 = crate::sensors::reject::snapshot()
            .into_iter()
            .filter(|(l, _)| l == "test")
            .map(|(_, n)| n)
            .sum();
        assert_eq!(rejected, 1, "the short one counted");
    }

    /// A pass reads at most [`PASS_MAX`] records, then sends and reads on
    /// without a wait (a producer that keeps the ring full does not hold
    /// the sends back).
    #[test]
    fn a_full_ring_is_read_in_passes_without_a_wait() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let mut specs = nn_core::bus::SPECS;
        specs[0].capacity = 8 * PASS_MAX;
        let (tx, mut rx) = crate::sensors::bus::channel_with(specs);
        let stop = Arc::new(AtomicBool::new(false));
        let n = (PASS_MAX * 2 + 3) as u32;
        let mut ring = FakeRing {
            records: (0..n).map(rec).collect(),
            waits: 0,
            stop_after: 1,
            stop: Arc::clone(&stop),
            later: VecDeque::new(),
        };
        let mut decode = decode_pid;
        run_ring("full", 4, &mut ring, &tx, rt.handle(), &stop, &mut decode).unwrap();
        assert_eq!(ring.waits, 1, "only once read empty");
        assert_eq!(std::iter::from_fn(|| rx.try_recv()).count(), n as usize);
    }

    /// A closed bus ends the pump (the agent stops), its stop flag too, and
    /// the thread is then finished — what SNS-001's check sees.
    #[test]
    fn a_closed_bus_or_the_stop_ends_the_pump() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (tx, rx) = channel();
        drop(rx);
        let stop = Arc::new(AtomicBool::new(false));
        let mut ring = FakeRing {
            records: (0..3).map(rec).collect(),
            waits: 0,
            stop_after: usize::MAX,
            stop: Arc::clone(&stop),
            later: VecDeque::new(),
        };
        let mut decode = decode_pid;
        run_ring("closed", 4, &mut ring, &tx, rt.handle(), &stop, &mut decode).unwrap();
        assert_eq!(ring.waits, 0, "ended at the first send");

        let t = PumpThread::spawn("stopper", |stop| {
            while !stop.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(())
        })
        .unwrap();
        let p = Pump::Thread(t);
        assert!(!p.is_finished());
        p.stop();
        let started = std::time::Instant::now();
        while !p.is_finished() {
            assert!(started.elapsed() < STOP_WITHIN, "it stops");
            std::thread::sleep(Duration::from_millis(5));
        }
        let failed = Pump::Thread(
            PumpThread::spawn("failer", |_| Err(io::Error::other("ring gone"))).unwrap(),
        );
        let started = std::time::Instant::now();
        while !failed.is_finished() {
            assert!(started.elapsed() < STOP_WITHIN, "a failed pump is finished");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// `poll(2)` on a descriptor with nothing to read returns after its
    /// timeout; with data, at once.
    #[test]
    fn the_wait_is_poll_with_its_timeout() {
        let mut fds = [0i32; 2];
        // SAFETY: a pipe into a valid two-element array.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let started = std::time::Instant::now();
        wait_readable(fds[0], 30).unwrap();
        assert!(started.elapsed() >= Duration::from_millis(25));
        // SAFETY: one byte from a valid buffer into the pipe's write end.
        assert_eq!(unsafe { libc::write(fds[1], [1u8].as_ptr().cast(), 1) }, 1);
        let started = std::time::Instant::now();
        wait_readable(fds[0], 5_000).unwrap();
        assert!(started.elapsed() < Duration::from_millis(1_000));
        // SAFETY: closing the two descriptors this test opened.
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }
}
