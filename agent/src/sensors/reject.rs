//! Malformed ring-buffer records: a coalesced WARN and a process-wide count
//! per ring, shown by `nn-admin status` next to the ring drops.
//!
//! External audit SNS-008: the open-sensor pump dropped short records at
//! debug level with no counter, while the multiplexer pumps coalesced them
//! into a WARN. Every pump now goes through [`RejectThrottle`], and every
//! rejected record is counted.

use parking_lot::Mutex;
use tracing::warn;

/// `(ring label, records rejected since boot)`, in first-seen order.
static REJECTED: Mutex<Vec<(&'static str, u64)>> = Mutex::new(Vec::new());

fn count(label: &'static str) {
    let mut v = REJECTED.lock();
    match v.iter_mut().find(|(l, _)| *l == label) {
        Some((_, n)) => *n += 1,
        None => v.push((label, 1)),
    }
}

/// Records rejected since boot, per ring (only rings that rejected one).
pub fn snapshot() -> Vec<(String, u64)> {
    REJECTED
        .lock()
        .iter()
        .map(|(l, n)| (l.to_string(), *n))
        .collect()
}

/// Records rejected since boot, every ring.
pub fn total() -> u64 {
    REJECTED.lock().iter().map(|(_, n)| n).sum()
}

/// Coalesces malformed-ringbuf-entry WARNs to at most one per second with a
/// running dropped-count. A ring whose records this pump cannot decode
/// rejects every entry and would flood the journal at hundreds/sec, filling
/// the LogNamespace `SystemMaxUse` cap and vacuuming real telemetry out of
/// the retention window. A sensor fault must never DoS its own log. Used by
/// every ringbuf pump, the open-sensor pump included.
///
/// External audit SNS-015: the case this was written for, catalog BUG-024
/// (`FS_PROTECT_EVENTS` pinned and reused across a restart, its positions
/// out of step with the new consumer), is history: every event ring is
/// process-local per boot, and its producers are attached fresh with it
/// (`sensors::multiplexer`, `no_event_ring_is_pinned`). The eBPF object is
/// embedded in the agent, so its records and this agent's decoders come
/// from one build: a rejected record is a defect to report.
pub(crate) struct RejectThrottle {
    count: u64,
    last_log: Option<std::time::Instant>,
    last_got: usize,
}

impl RejectThrottle {
    pub(crate) fn new() -> Self {
        Self {
            count: 0,
            last_log: None,
            last_got: 0,
        }
    }

    /// Record one rejected entry (counted for `nn-admin status`); emit a
    /// coalesced WARN at most 1/sec.
    pub(crate) fn record(&mut self, label: &'static str, expected: usize, got: usize) {
        count(label);
        self.count += 1;
        self.last_got = got;
        if self.due() {
            self.emit(label, expected);
        }
    }

    /// Flush a residual count once the ring goes quiet, so a final burst is
    /// not silently dropped from the log.
    pub(crate) fn flush_idle(&mut self, label: &str, expected: usize) {
        if self.count > 0 && self.due() {
            self.emit(label, expected);
        }
    }

    fn due(&self) -> bool {
        self.last_log
            .is_none_or(|t| t.elapsed() >= std::time::Duration::from_secs(1))
    }

    fn emit(&mut self, label: &str, expected: usize) {
        warn!(
            label,
            rejected = self.count,
            expected,
            got = self.last_got,
            "ringbuf entries rejected — records of a size this pump does not decode, \
             dropped and counted (nn-admin status); one WARN per second at most per ring, \
             `rejected` = entries since the previous WARN. The kernel program and the agent \
             come from one build, so any count is a defect to report"
        );
        self.count = 0;
        self.last_log = Some(std::time::Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rejected_record_is_counted_per_ring() {
        let mut t = RejectThrottle::new();
        let before = total();
        for _ in 0..5 {
            t.record("reject_test_ring", 64, 8);
        }
        // The WARN is coalesced (first one only within the second), the
        // count is not.
        assert_eq!(t.count, 4);
        let n = snapshot()
            .into_iter()
            .find(|(l, _)| l == "reject_test_ring")
            .map(|(_, n)| n);
        assert_eq!(n, Some(5));
        assert!(total() >= before + 5);
    }
}
