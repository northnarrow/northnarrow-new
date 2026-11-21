//! Lot 379 (pre-alpha Phase 7, F7-1; Phase 3-bis, F3b-6): the signed
//! integrity findings `nn-admin status` holds.
//!
//! The agent signed a cut or rewritten chain (`chain_truncated`,
//! `chain_verify_failed`), an unauthorized overlay, a modified default list,
//! a mount laid over its paths… as `integrity_drift` rows of its audit log,
//! and `nn-admin status` said `sensors: OK — no degradation` all the same:
//! only the journal's ERROR and `nn-admin chain verify` told. The audit log
//! now keeps, from its own rows, the findings that hold
//! ([`AuditLog::held`](crate::audit::AuditLog::held)), at its open (the
//! walk of the chain, so a restart does not launder them) and at each
//! append; its host is told at each change
//! ([`ChainHost::integrity_held`](crate::chain_host::ChainHost::integrity_held))
//! and the agent shows them as degradations — `sensors: DEGRADED`, the trust
//! level at most L2, the capability manifest's degradations.
//!
//! The rule ([`hold_of`]):
//!
//! - a row of the **evidence** class ([`EVIDENCE_KINDS`]: a chain cut,
//!   rewritten, unverifiable or missing, the witness chain broken, the
//!   agent's identity changed, the overlays' rollback floor lost) is held
//!   until a signed operator acknowledgement covers it ([`ACK_OP`], `nn-admin
//!   integrity acknowledge --through <row>`): the alteration stays in the
//!   evidence for good, no later state is clean;
//! - any other finding ([`Hold::WhileFound`]: an unauthorized overlay, a
//!   modified default list, the integrity round's drifts, an event of the
//!   run) is held while it is found: until the check that signed it signs
//!   its end (`integrity_drift_cleared`, the same kind and detail), or the
//!   next start (its `agent_boot`), which checks again and signs it again
//!   if it still holds — or until an acknowledgement covers it;
//! - not held ([`NOT_HELD_KINDS`]): the degradations the registry shows
//!   already, with their own end (`subsystem_degraded`, the pin lock, the
//!   profile downgrade…), and a row that is no finding (`result` other than
//!   `detected` or `failed`: a note, a repair, an end).
//!
//! A row that ends a hold (an acknowledgement, a `cleared`, an `agent_boot`)
//! counts only when its signature verifies with the log's key: a line
//! appended by hand to the file launders nothing. A finding row is held
//! whatever its signature (holding more is the safe side; a forged row
//! breaks the chain, which is a finding of its own).

use crate::audit::{AuditEntry, INTEGRITY_CLEARED_OP, INTEGRITY_DRIFT_OP};

/// The op of a signed operator acknowledgement of the held findings
/// (`nn-admin integrity acknowledge`): `extra.through_row`, the newest row
/// it covers; `result` `success`.
pub const ACK_OP: &str = "integrity_acknowledged";

/// The degradation source the agent shows the held findings under.
pub const SOURCE: &str = "integrity";

/// Findings listed at most; past it they are counted ([`Held::more`]).
pub const MAX_HELD: usize = 16;

/// The longest detail a held line carries (characters).
pub const DETAIL_CHARS: usize = 160;

/// How long a finding is held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hold {
    /// The evidence is altered: held until an acknowledgement covers it.
    UntilAcknowledged,
    /// Held while the check that signed it finds it (its `cleared` row, or
    /// the next start), or until an acknowledgement covers it.
    WhileFound,
    /// Not held: shown by its own degradation, or no finding.
    NotHeld,
}

/// The evidence class: the signed evidence itself altered, missing or not
/// verifiable. Every kind the start signs before its own `agent_boot` row
/// is here (the chains' boot check, the identity, the rollback floor): one
/// held [`Hold::WhileFound`] would end at that row.
pub const EVIDENCE_KINDS: &[&str] = &[
    // the chains' boot check and run-time anchor (`ChainFinding`)
    "chain_truncated",
    "chain_rewritten",
    "chain_missing",
    "chain_archives_missing",
    "active_file_missing",
    "chain_sequence_broken",
    "chain_lines_unverified",
    "chain_verify_failed",
    "chain_heads_missing",
    "chain_heads_unverified",
    // unreadable lines skipped at the open of a chain (DEC-006)
    "chain_lines_unreadable",
    // the watchdog's witness chain: a row changed, removed or not one
    "witness_chain_broken",
    // EVD-020: an identity other than the one the chain's last row carries
    "agent_id_changed",
    // LLMR-014: the overlays' rollback floor reset (its anchor not found)
    "overlay_rollback_floor_unavailable",
];

/// The kinds of `integrity_drift` rows that are not held, and why: each is
/// a degradation of the registry already, kept while it holds and
/// withdrawn by its own finder.
pub const NOT_HELD_KINDS: &[(&str, &str)] = &[
    (
        "subsystem_degraded",
        "the degradation registry's own row: shown while it holds, withdrawn when it ends",
    ),
    (
        "profile_downgraded",
        "kept by the start until something signed answers it (lot 345, the review of #553)",
    ),
    (
        "pin_lock_missing",
        "the pin lock's degradation (lot 367) shows it while the lock is not in place",
    ),
    (
        "pin_lock_changed",
        "the pin lock's degradation (lot 367) shows it while the lock is not in place",
    ),
    (
        "agent_restart_loop",
        "reported to the registry by the integrity round for the rest of the run (lot 353)",
    ),
    (
        "watchdog_pin_handle_failed",
        "reported to the registry by the integrity round (lot 359)",
    ),
];

/// How a signed `integrity_drift` row of `kind` with `result` is held.
pub fn hold_of(kind: &str, result: &str) -> Hold {
    if !matches!(result, "detected" | "failed") {
        return Hold::NotHeld;
    }
    if NOT_HELD_KINDS.iter().any(|(k, _)| *k == kind) {
        return Hold::NotHeld;
    }
    if EVIDENCE_KINDS.contains(&kind) {
        Hold::UntilAcknowledged
    } else {
        Hold::WhileFound
    }
}

/// One held finding: the rows of one kind about one subject.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeldFinding {
    pub kind: String,
    /// The chain it is about (`detections`, `audit`…), else its detail.
    pub subject: String,
    /// The newest row's detail, cut to [`DETAIL_CHARS`].
    pub detail: String,
    pub hold: Hold,
    /// When it was first signed (since the last end of its hold).
    pub first_ts: String,
    /// The newest row's time and position in the chain (0-based).
    pub last_ts: String,
    pub last_row: u64,
    /// Rows signed about it.
    pub rows: u64,
}

impl HeldFinding {
    /// The line `nn-admin status` lists (under [`SOURCE`]).
    pub fn line(&self) -> String {
        let about = if self.subject == self.detail {
            String::new()
        } else {
            format!(" ({})", self.subject)
        };
        let times = if self.rows > 1 {
            format!(
                "signed {} times since {}, last {} (audit row {})",
                self.rows, self.first_ts, self.last_ts, self.last_row
            )
        } else {
            format!("signed {} (audit row {})", self.last_ts, self.last_row)
        };
        let until = match self.hold {
            Hold::UntilAcknowledged => {
                "held until acknowledged (`nn-admin integrity acknowledge --through <row>`)"
            }
            _ => "held while found, or until acknowledged",
        };
        format!("{}{about} — {times} — {until}: {}", self.kind, self.detail)
    }
}

/// The held findings of one chain, as its rows say.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Held {
    findings: Vec<HeldFinding>,
    /// Findings past [`MAX_HELD`] (counted, newest row of each class).
    more: [(u64, u64); 2],
}

/// The text of `extra[key]`, if a string.
fn text<'a>(extra: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    extra.get(key).and_then(|v| v.as_str())
}

fn cut(s: &str) -> String {
    if s.chars().count() <= DETAIL_CHARS {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(DETAIL_CHARS).collect();
        out.push('…');
        out
    }
}

fn class(hold: Hold) -> usize {
    usize::from(hold == Hold::WhileFound)
}

impl Held {
    /// The findings held, oldest first.
    pub fn findings(&self) -> &[HeldFinding] {
        &self.findings
    }

    /// Rows of findings held past [`MAX_HELD`], not listed.
    pub fn more(&self) -> u64 {
        self.more[0].0 + self.more[1].0
    }

    /// Nothing held.
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty() && self.more() == 0
    }

    /// The lines `nn-admin status` lists: one a finding, then one counting
    /// those not listed.
    pub fn lines(&self) -> Vec<String> {
        let mut out: Vec<String> = self.findings.iter().map(HeldFinding::line).collect();
        if self.more() > 0 {
            out.push(format!(
                "… and {} more held integrity row(s) (in the signed audit log)",
                self.more()
            ));
        }
        out
    }

    /// The newest row of a held finding (what an acknowledgement of them
    /// all names), `None` when nothing is held.
    pub fn newest_row(&self) -> Option<u64> {
        let listed = self.findings.iter().map(|f| f.last_row).max();
        let counted = self
            .more
            .iter()
            .filter(|(n, _)| *n > 0)
            .map(|(_, row)| *row)
            .max();
        listed.max(counted)
    }

    /// How many held findings an acknowledgement through `through` covers
    /// (their newest row at or before it).
    pub fn covered_by(&self, through: u64) -> u64 {
        let listed = self
            .findings
            .iter()
            .filter(|f| f.last_row <= through)
            .count() as u64;
        let counted: u64 = self
            .more
            .iter()
            .filter(|(n, row)| *n > 0 && *row <= through)
            .map(|(n, _)| *n)
            .sum();
        listed + counted
    }

    /// Row `row` of the chain (0-based), `entry`: whether what is held
    /// changed. `genuine` says whether a row's signature verifies with the
    /// log's key; asked only of the rows that end a hold.
    pub fn observe(
        &mut self,
        row: u64,
        entry: &AuditEntry,
        genuine: &dyn Fn(&AuditEntry) -> bool,
    ) -> bool {
        match entry.op.as_str() {
            INTEGRITY_DRIFT_OP => self.finding(row, entry),
            INTEGRITY_CLEARED_OP => {
                let (Some(kind), Some(detail)) =
                    (text(&entry.extra, "kind"), text(&entry.extra, "detail"))
                else {
                    return false;
                };
                let subject = cut(detail);
                let before = self.findings.len();
                if !self
                    .findings
                    .iter()
                    .any(|f| f.hold == Hold::WhileFound && f.kind == kind && f.subject == subject)
                    || !genuine(entry)
                {
                    return false;
                }
                self.findings.retain(|f| {
                    !(f.hold == Hold::WhileFound && f.kind == kind && f.subject == subject)
                });
                before != self.findings.len()
            }
            // a start checks again: what it still finds, it signs again
            "agent_boot" if entry.result == "success" => {
                let found =
                    self.findings.iter().any(|f| f.hold == Hold::WhileFound) || self.more[1].0 > 0;
                if !found || !genuine(entry) {
                    return false;
                }
                self.findings.retain(|f| f.hold != Hold::WhileFound);
                self.more[1] = (0, 0);
                true
            }
            ACK_OP if entry.result == "success" => {
                let Some(through) = entry.extra.get("through_row").and_then(|v| v.as_u64()) else {
                    return false;
                };
                // never past the acknowledgement's own row
                let through = through.min(row.saturating_sub(1));
                if self.covered_by(through) == 0 || !genuine(entry) {
                    return false;
                }
                self.findings.retain(|f| f.last_row > through);
                for m in &mut self.more {
                    if m.0 > 0 && m.1 <= through {
                        *m = (0, 0);
                    }
                }
                true
            }
            _ => false,
        }
    }

    fn finding(&mut self, row: u64, entry: &AuditEntry) -> bool {
        let Some(kind) = text(&entry.extra, "kind") else {
            return false;
        };
        let hold = hold_of(kind, &entry.result);
        if hold == Hold::NotHeld {
            return false;
        }
        let detail = cut(text(&entry.extra, "detail").unwrap_or(""));
        let subject = text(&entry.extra, "chain")
            .map(str::to_string)
            .unwrap_or_else(|| detail.clone());
        if let Some(f) = self
            .findings
            .iter_mut()
            .find(|f| f.kind == kind && f.subject == subject)
        {
            f.detail = detail;
            f.last_ts = entry.ts.clone();
            f.last_row = row;
            f.rows += 1;
            // an evidence row also holds what it says until acknowledged
            if hold == Hold::UntilAcknowledged {
                f.hold = hold;
            }
            return true;
        }
        if self.findings.len() >= MAX_HELD {
            let m = &mut self.more[class(hold)];
            m.0 += 1;
            m.1 = row;
            return true;
        }
        self.findings.push(HeldFinding {
            kind: kind.to_string(),
            subject,
            detail,
            hold,
            first_ts: entry.ts.clone(),
            last_ts: entry.ts.clone(),
            last_row: row,
            rows: 1,
        });
        true
    }
}

#[cfg(test)]
mod tests;
