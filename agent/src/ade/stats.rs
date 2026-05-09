//! Latency and outcome counters for ADE inferences.
//!
//! Uses a fixed-size circular buffer of the last 256 latencies so
//! p50/p95/p99 can be computed without external metrics deps. The
//! buffer is cheap (256 × `u64` = 2 KiB) and accurate enough for
//! Tappa 6 demos; a proper histogram (HDR / t-digest) is a follow-up.

use std::sync::atomic::{AtomicU64, Ordering};

const LATENCY_BUF: usize = 256;

#[derive(Debug, Default)]
pub struct AdeStats {
    pub total_inferences: AtomicU64,
    pub successful_verdicts: AtomicU64,
    pub malformed_outputs: AtomicU64,
    pub timeouts: AtomicU64,
    pub backend_errors: AtomicU64,
    /// Cumulative latency in milliseconds — divide by `total_inferences`
    /// to get the running mean.
    pub total_latency_ms: AtomicU64,
    latency_ring: parking_lot::Mutex<LatencyRing>,
}

#[derive(Debug)]
struct LatencyRing {
    buf: [u64; LATENCY_BUF],
    cursor: usize,
    filled: usize,
}

impl Default for LatencyRing {
    fn default() -> Self {
        Self {
            buf: [0; LATENCY_BUF],
            cursor: 0,
            filled: 0,
        }
    }
}

/// Snapshot view of the stats for logging / health endpoints.
#[derive(Debug, Clone, Copy)]
pub struct AdeStatsSnapshot {
    pub total_inferences: u64,
    pub successful_verdicts: u64,
    pub malformed_outputs: u64,
    pub timeouts: u64,
    pub backend_errors: u64,
    pub avg_latency_ms: f64,
    pub p50_latency_ms: u64,
    pub p95_latency_ms: u64,
    pub p99_latency_ms: u64,
}

impl AdeStats {
    pub fn record_success(&self, latency_ms: u64) {
        self.total_inferences.fetch_add(1, Ordering::Relaxed);
        self.successful_verdicts.fetch_add(1, Ordering::Relaxed);
        self.total_latency_ms
            .fetch_add(latency_ms, Ordering::Relaxed);
        self.push_latency(latency_ms);
    }

    pub fn record_malformed(&self, latency_ms: u64) {
        self.total_inferences.fetch_add(1, Ordering::Relaxed);
        self.malformed_outputs.fetch_add(1, Ordering::Relaxed);
        self.total_latency_ms
            .fetch_add(latency_ms, Ordering::Relaxed);
        self.push_latency(latency_ms);
    }

    pub fn record_timeout(&self) {
        self.total_inferences.fetch_add(1, Ordering::Relaxed);
        self.timeouts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_backend_error(&self) {
        self.total_inferences.fetch_add(1, Ordering::Relaxed);
        self.backend_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> AdeStatsSnapshot {
        let total = self.total_inferences.load(Ordering::Relaxed);
        let cum = self.total_latency_ms.load(Ordering::Relaxed);
        let avg = if total == 0 {
            0.0
        } else {
            cum as f64 / total as f64
        };
        let (p50, p95, p99) = self.percentiles();
        AdeStatsSnapshot {
            total_inferences: total,
            successful_verdicts: self.successful_verdicts.load(Ordering::Relaxed),
            malformed_outputs: self.malformed_outputs.load(Ordering::Relaxed),
            timeouts: self.timeouts.load(Ordering::Relaxed),
            backend_errors: self.backend_errors.load(Ordering::Relaxed),
            avg_latency_ms: avg,
            p50_latency_ms: p50,
            p95_latency_ms: p95,
            p99_latency_ms: p99,
        }
    }

    fn push_latency(&self, ms: u64) {
        let mut ring = self.latency_ring.lock();
        let cursor = ring.cursor;
        ring.buf[cursor] = ms;
        ring.cursor = (cursor + 1) % LATENCY_BUF;
        if ring.filled < LATENCY_BUF {
            ring.filled += 1;
        }
    }

    fn percentiles(&self) -> (u64, u64, u64) {
        let ring = self.latency_ring.lock();
        if ring.filled == 0 {
            return (0, 0, 0);
        }
        let mut buf = ring.buf[..ring.filled].to_vec();
        drop(ring);
        buf.sort_unstable();
        let p = |q: f64| -> u64 {
            let idx = ((buf.len() as f64) * q).floor() as usize;
            let idx = idx.min(buf.len() - 1);
            buf[idx]
        };
        (p(0.50), p(0.95), p(0.99))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_with_uniform_distribution() {
        let stats = AdeStats::default();
        for i in 1..=100u64 {
            stats.record_success(i);
        }
        let snap = stats.snapshot();
        assert_eq!(snap.total_inferences, 100);
        assert_eq!(snap.successful_verdicts, 100);
        // p50 of 1..=100 floored is 50, p95 is 95, p99 is 99
        assert!(snap.p50_latency_ms >= 49 && snap.p50_latency_ms <= 51);
        assert!(snap.p95_latency_ms >= 94 && snap.p95_latency_ms <= 96);
        assert!(snap.p99_latency_ms >= 98 && snap.p99_latency_ms <= 100);
        assert!((snap.avg_latency_ms - 50.5).abs() < 1.0);
    }

    #[test]
    fn empty_snapshot_is_zero() {
        let stats = AdeStats::default();
        let snap = stats.snapshot();
        assert_eq!(snap.total_inferences, 0);
        assert_eq!(snap.p50_latency_ms, 0);
        assert!((snap.avg_latency_ms - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn malformed_and_timeout_counted_separately() {
        let stats = AdeStats::default();
        stats.record_success(100);
        stats.record_malformed(80);
        stats.record_timeout();
        stats.record_backend_error();
        let snap = stats.snapshot();
        assert_eq!(snap.total_inferences, 4);
        assert_eq!(snap.successful_verdicts, 1);
        assert_eq!(snap.malformed_outputs, 1);
        assert_eq!(snap.timeouts, 1);
        assert_eq!(snap.backend_errors, 1);
    }
}
