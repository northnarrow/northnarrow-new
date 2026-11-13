//! Lot 341 (alpha 2/4): today's detection records, counted as the writer
//! appends them to the signed chain — the summary at the top of
//! `nn-admin status --key`: records of the UTC day by severity, and the
//! responses the no-enforcement gate suppressed (`would have: <action>`).
//!
//! The count starts at the agent's start (or at 00:00 UTC, whichever is
//! later) and starts again at each UTC midnight; the chain itself
//! (`nn-admin detections`) holds every record.

use std::collections::BTreeMap;

use chrono::{DateTime, NaiveDate, Utc};
use nn_model::Severity;
use nn_proto::admin_protocol::RecordsToday;

use nn_core::response::profile::WOULD_HAVE_PREFIX;

/// The counts of one UTC day.
#[derive(Debug, Clone)]
pub struct TodayCounts {
    day: NaiveDate,
    since: DateTime<Utc>,
    by_severity: [u64; 4],
    would_have: BTreeMap<String, u64>,
}

/// The severities, highest first, with their slot.
const SEVERITIES: [(Severity, &str); 4] = [
    (Severity::Critical, "Critical"),
    (Severity::High, "High"),
    (Severity::Medium, "Medium"),
    (Severity::Low, "Low"),
];

fn slot(s: Severity) -> usize {
    SEVERITIES
        .iter()
        .position(|(v, _)| *v == s)
        .unwrap_or(SEVERITIES.len() - 1)
}

/// The action a record's `response` says the gate suppressed
/// (`would have: KillProcess` → `KillProcess`); `None` for any other text.
pub fn would_have_action(response: &str) -> Option<&str> {
    response
        .strip_prefix(WOULD_HAVE_PREFIX)
        .map(|a| a.split_whitespace().next().unwrap_or(""))
        .filter(|a| !a.is_empty())
}

impl TodayCounts {
    /// Counting from `start` (the agent's start).
    pub fn new(start: DateTime<Utc>) -> Self {
        Self {
            day: start.date_naive(),
            since: start,
            by_severity: [0; 4],
            would_have: BTreeMap::new(),
        }
    }

    /// A new UTC day starts the count again, from its midnight.
    fn roll(&mut self, now: DateTime<Utc>) {
        let today = now.date_naive();
        if today != self.day {
            self.day = today;
            self.since = today
                .and_hms_opt(0, 0, 0)
                .map(|t| t.and_utc())
                .unwrap_or(now);
            self.by_severity = [0; 4];
            self.would_have.clear();
        }
    }

    /// One record appended at `now`.
    pub fn note(&mut self, now: DateTime<Utc>, severity: Severity, response: &str) {
        self.roll(now);
        self.by_severity[slot(severity)] += 1;
        if let Some(action) = would_have_action(response) {
            *self.would_have.entry(action.to_string()).or_default() += 1;
        }
    }

    /// What `nn-admin status` shows, as of `now`.
    pub fn snapshot(&mut self, now: DateTime<Utc>) -> RecordsToday {
        self.roll(now);
        let mut would_have: Vec<(String, u64)> = self
            .would_have
            .iter()
            .map(|(a, n)| (a.clone(), *n))
            .collect();
        // most first, then by name
        would_have.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        RecordsToday {
            day: self.day.format("%Y-%m-%d").to_string(),
            since: self.since.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            by_severity: SEVERITIES
                .iter()
                .zip(self.by_severity)
                .filter(|(_, n)| *n > 0)
                .map(|((_, name), n)| (name.to_string(), n))
                .collect(),
            would_have,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(h: u32, m: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 13, h, m, 0).unwrap()
    }

    /// Named (lot 341): today's records by severity, highest first, and the
    /// suppressed responses by action — a record that ran or logged is no
    /// "would have".
    #[test]
    fn today_counts_records_by_severity_and_what_would_have_run() {
        let mut c = TodayCounts::new(at(9, 30));
        c.note(at(9, 31), Severity::Low, "none");
        c.note(at(9, 32), Severity::High, "would have: KillProcessTree");
        c.note(at(9, 33), Severity::High, "would have: KillProcess");
        c.note(at(9, 34), Severity::Critical, "would have: KillProcessTree");
        c.note(at(9, 35), Severity::Medium, "KillProcess (already gone)");
        c.note(at(9, 36), Severity::Low, "suppressed (detect-only)");
        let s = c.snapshot(at(10, 0));
        assert_eq!(s.day, "2026-11-13");
        assert_eq!(s.since, "2026-11-13T09:30:00Z");
        assert_eq!(
            s.by_severity,
            vec![
                ("Critical".to_string(), 1),
                ("High".to_string(), 2),
                ("Medium".to_string(), 1),
                ("Low".to_string(), 2),
            ]
        );
        assert_eq!(
            s.would_have,
            vec![
                ("KillProcessTree".to_string(), 2),
                ("KillProcess".to_string(), 1),
            ]
        );
    }

    /// A new UTC day counts from its midnight, from zero.
    #[test]
    fn a_new_day_starts_the_count_again() {
        let mut c = TodayCounts::new(at(23, 0));
        c.note(at(23, 10), Severity::High, "would have: Quarantine");
        let next = Utc.with_ymd_and_hms(2026, 11, 14, 0, 5, 0).unwrap();
        let s = c.snapshot(next);
        assert_eq!(s.day, "2026-11-14");
        assert_eq!(s.since, "2026-11-14T00:00:00Z");
        assert!(s.by_severity.is_empty());
        assert!(s.would_have.is_empty());
        c.note(next, Severity::Low, "none");
        assert_eq!(c.snapshot(next).by_severity, vec![("Low".to_string(), 1)]);
    }

    #[test]
    fn only_the_gate_s_text_is_a_would_have() {
        assert_eq!(
            would_have_action("would have: KillProcess"),
            Some("KillProcess")
        );
        assert_eq!(would_have_action("would have: "), None);
        assert_eq!(would_have_action("KillProcess"), None);
        assert_eq!(would_have_action("none"), None);
    }
}
