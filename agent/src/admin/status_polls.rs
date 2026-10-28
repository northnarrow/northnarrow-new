//! External audit ASK-009 (lab PR 213): the unsigned `status` polling,
//! summarised in the signed audit log.
//!
//! `status` needs no signature — the watchdog pings it, COMBAT recovery
//! reads it — so it was the one request a local root could send without a
//! trace. It now carries no telemetry (the signed `TelemetryStatusRequest`
//! does), and each peer that polls it gets one signed `status_polled` row per
//! [`POLL_WINDOW`]: the first unsigned `status` of a peer, identified by its
//! uid and the `comm` it gives itself, writes a row at once, with the number
//! of requests in that peer's previous window; the rest of the window is
//! counted, not written. The registered watchdog is not recorded: it is
//! known by its pid as the agent verified it (pidfile, executable and start
//! time — the pid the agent puts in `PROTECTED_PIDS`), never by its `comm`,
//! which any process can take. At most [`MAX_PEERS`] peers are tracked; past
//! them, the newcomers share one window (`"peers_over_cap": true`), so
//! changing `comm` at each request buys one row per window, not silence and
//! not memory.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use super::AuditClient;
use crate::audit::AuditEntryDraft;
use crate::posture::ExemptPids;

/// The audit `op` of the summary row.
pub const STATUS_POLLED_OP: &str = "status_polled";

/// One row per peer per window.
pub const POLL_WINDOW: Duration = Duration::from_secs(3600);

/// Peers tracked at once; past them the newcomers share one window.
pub const MAX_PEERS: usize = 64;

/// The `comm` of the shared window of the peers past [`MAX_PEERS`].
const OVER_CAP: &str = "<peers over the cap>";

/// One peer's window: when it opened (its row was written) and the
/// requests counted in it, that first one included.
struct Window {
    opened: Instant,
    polls: u64,
}

/// The unsigned `status` requests of each peer, per [`POLL_WINDOW`].
pub struct StatusPolls {
    exempt: ExemptPids,
    window: Duration,
    peers: Mutex<HashMap<(u32, String), Window>>,
}

impl Default for StatusPolls {
    /// No exemption (tests and the legacy serve entry points): the
    /// watchdog's pings are summarised like any peer's.
    fn default() -> Self {
        Self::new(ExemptPids::default())
    }
}

impl StatusPolls {
    /// `exempt`: the agent and the verified watchdog, whose requests are
    /// not recorded.
    pub fn new(exempt: ExemptPids) -> Self {
        Self::with_window(exempt, POLL_WINDOW)
    }

    pub(crate) fn with_window(exempt: ExemptPids, window: Duration) -> Self {
        Self {
            exempt,
            window,
            peers: Mutex::new(HashMap::new()),
        }
    }

    /// One unsigned `status` from `client` at `now`: the row to append when
    /// it opens the peer's window, else `None` (counted).
    pub(crate) fn note(&self, client: &AuditClient, now: Instant) -> Option<AuditEntryDraft> {
        if self.exempt.is_exempt(client.pid) {
            return None;
        }
        let mut peers = self.peers.lock();
        let mut key = (client.uid, client.comm.clone());
        let mut over_cap = false;
        if !peers.contains_key(&key) && peers.len() >= MAX_PEERS {
            let window = self.window;
            peers.retain(|_, w| now.saturating_duration_since(w.opened) < window);
            if peers.len() >= MAX_PEERS {
                key = (u32::MAX, OVER_CAP.to_string());
                over_cap = true;
            }
        }
        let previous = match peers.get_mut(&key) {
            Some(w) if now.saturating_duration_since(w.opened) < self.window => {
                w.polls = w.polls.saturating_add(1);
                return None;
            }
            Some(w) => Some(w.polls),
            None => None,
        };
        peers.insert(
            key,
            Window {
                opened: now,
                polls: 1,
            },
        );
        drop(peers);
        Some(AuditEntryDraft {
            op: STATUS_POLLED_OP.to_string(),
            extra: serde_json::json!({
                "window_secs": self.window.as_secs(),
                // requests in this peer's previous window, its first
                // included; null for a peer's first row
                "previous_window_polls": previous,
                "peers_over_cap": over_cap,
            }),
            key_fp: String::new(),
            cosigner_fps: Vec::new(),
            result: "success".to_string(),
            client_pid: client.pid,
            client_uid: client.uid,
            client_comm: client.comm.clone(),
            client_exe: client.exe.clone(),
        })
    }

    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.peers.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(pid: u32, comm: &str) -> AuditClient {
        AuditClient {
            pid,
            uid: 0,
            comm: comm.to_string(),
            exe: Some("/usr/local/bin/nn-admin".to_string()),
        }
    }

    /// External audit ASK-009: a burst of 100 unsigned `status` from one
    /// peer is one row; the next window's first request writes the next,
    /// with the count of the previous window.
    #[test]
    fn a_burst_from_one_peer_is_one_row_per_window() {
        let polls = StatusPolls::new(ExemptPids::default());
        let t0 = Instant::now();
        let rows: Vec<AuditEntryDraft> = (0..100)
            .filter_map(|i| {
                polls.note(
                    &peer(4000 + i, "nn-admin"),
                    t0 + Duration::from_secs(i as u64),
                )
            })
            .collect();
        assert_eq!(rows.len(), 1, "one row for the burst");
        let row = &rows[0];
        assert_eq!(row.op, STATUS_POLLED_OP);
        assert_eq!(row.client_pid, 4000);
        assert_eq!(row.client_comm, "nn-admin");
        assert_eq!(row.client_exe.as_deref(), Some("/usr/local/bin/nn-admin"));
        assert_eq!(row.result, "success");
        assert!(row.key_fp.is_empty(), "unsigned: no key");
        assert_eq!(row.extra["previous_window_polls"], serde_json::Value::Null);
        assert_eq!(row.extra["window_secs"], 3600);
        assert_eq!(row.extra["peers_over_cap"], false);
        // Still inside the hour: counted.
        assert!(polls
            .note(&peer(4200, "nn-admin"), t0 + Duration::from_secs(3599))
            .is_none());
        let next = polls
            .note(&peer(4300, "nn-admin"), t0 + POLL_WINDOW)
            .expect("the next window opens with a row");
        assert_eq!(next.extra["previous_window_polls"], 101);
        assert_eq!(next.client_pid, 4300);
    }

    /// Peers are told apart by uid and comm (another tool polling is
    /// recorded at its first request, not hidden in the operator's window).
    #[test]
    fn each_peer_has_its_own_window() {
        let polls = StatusPolls::new(ExemptPids::default());
        let t0 = Instant::now();
        assert!(polls.note(&peer(10, "nn-admin"), t0).is_some());
        assert!(polls.note(&peer(11, "python3"), t0).is_some());
        let mut other_uid = peer(12, "nn-admin");
        other_uid.uid = 990;
        assert!(polls.note(&other_uid, t0).is_some());
        assert!(polls.note(&peer(13, "nn-admin"), t0).is_none());
        assert!(polls.note(&peer(14, "python3"), t0).is_none());
    }

    /// The registered watchdog's pings write nothing; the exemption is the
    /// pid the agent verified (with its start time), not the comm: another
    /// process named like the watchdog is recorded.
    #[test]
    fn the_registered_watchdog_is_not_recorded_a_namesake_is() {
        let me = std::process::id();
        let exempt = ExemptPids::with_agent(1);
        let start = std::fs::read_to_string(format!("/proc/{me}/stat"))
            .ok()
            .and_then(|s| s.rsplit_once(')').map(|(_, r)| r.to_string()))
            .and_then(|r| r.split_whitespace().nth(19).map(str::to_string))
            .and_then(|v| v.parse::<u64>().ok())
            .expect("own start time");
        exempt.set_watchdog(me, start);
        let polls = StatusPolls::new(exempt);
        let t0 = Instant::now();
        for i in 0..10 {
            assert!(polls
                .note(&peer(me, "northnarrow-wat"), t0 + Duration::from_secs(i))
                .is_none());
        }
        assert_eq!(polls.tracked(), 0);
        let namesake = polls
            .note(&peer(me + 1, "northnarrow-wat"), t0)
            .expect("a namesake is a peer like any other");
        assert_eq!(namesake.client_comm, "northnarrow-wat");
        // The agent's own pid is exempt too.
        assert!(polls.note(&peer(1, "northnarrow-age"), t0).is_none());
    }

    /// A peer changing its comm at each request fills the table, then
    /// shares one window: bounded memory, still a row per window.
    #[test]
    fn peers_past_the_cap_share_one_window() {
        let polls = StatusPolls::new(ExemptPids::default());
        let t0 = Instant::now();
        let rows = (0..MAX_PEERS + 50)
            .filter_map(|i| polls.note(&peer(100, &format!("x{i}")), t0))
            .collect::<Vec<_>>();
        assert_eq!(
            rows.len(),
            MAX_PEERS + 1,
            "one per tracked peer, one for the rest"
        );
        assert_eq!(rows[MAX_PEERS].extra["peers_over_cap"], true);
        assert_eq!(polls.tracked(), MAX_PEERS + 1);
        // Once the windows expire, a newcomer takes a freed slot.
        let later = polls
            .note(&peer(100, "late"), t0 + POLL_WINDOW)
            .expect("a row");
        assert_eq!(later.extra["peers_over_cap"], false);
        assert!(polls.tracked() <= MAX_PEERS + 1);
    }
}
