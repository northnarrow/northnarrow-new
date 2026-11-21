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
//! The rule ([`hold_of`]) — every kind the product signs is in one table
//! (the review of #586, P2-1: the default class held an admin key left on
//! the host, a stalled agent loop, the operator's own signed sysctl opt-out as
//! degradations, `sensors: DEGRADED` on every default install, which hid a
//! real one; the ratchet `xtask/tests/integrity_kinds.rs` fails on a kind
//! signed and in none):
//!
//! - a row of the **evidence** class ([`EVIDENCE_KINDS`]: a chain cut,
//!   rewritten, unverifiable or missing, the witness chain broken, the
//!   agent's identity changed, the overlays' rollback floor lost), a
//!   **death** of the agent's or the watchdog's role ([`DEATH_KINDS`]: a
//!   crash, a kill, an OOM, the watchdog gone; Phase 7b F7-6) or an
//!   attack-class **event** of the run ([`EVENT_KINDS`]: a forged shutdown
//!   marker, the admin socket removed or reached by a foreign peer; the
//!   review of #586, P3-2) is held until a signed operator acknowledgement
//!   covers it ([`ACK_OP`], `nn-admin integrity acknowledge --through
//!   <row>`): the alteration stays in the evidence for good, a death or an
//!   event is not undone by a later start, a host reboot included — no later
//!   state is clean;
//! - a **degradation** ([`DEGRADATION_KINDS`], [`Hold::WhileFound`]: an
//!   unauthorized overlay, a modified default list, the integrity round's
//!   drifts) is held while it is found: until the check that signed it signs
//!   its end (`integrity_drift_cleared`, the same kind and detail), or the
//!   next start (its `agent_boot`), which checks again and signs it again if
//!   it still holds — or until an acknowledgement covers it;
//! - an **advisory** ([`ADVISORY_KINDS`], [`Hold::Advisory`]: a state of the
//!   host or a choice of the operator that degrades no sensor — an admin key
//!   left on the host, the operator's signed sysctl opt-out, a pause of the
//!   whole machine) is kept as a degradation is, and shown on its own:
//!   never counted in `sensors`, the trust level or the manifest;
//! - not held ([`NOT_HELD_KINDS`]): the degradations the registry shows
//!   already, with their own end (`subsystem_degraded`, the pin lock, the
//!   profile downgrade, the host's harmful drop-ins…), and a row that is no
//!   finding (`result` other than `detected` or `failed`: a note, a repair,
//!   an end).
//!
//! A kind in no table (a row of another build) is held as a degradation
//! ([`UNKNOWN_KIND`]: the safe side).
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

/// How long a finding is held, and as what.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hold {
    /// The evidence is altered, a role died, an attack-class event: a
    /// degradation held until an acknowledgement covers it.
    UntilAcknowledged,
    /// A degradation held while the check that signed it finds it (its
    /// `cleared` row, or the next start), or until an acknowledgement
    /// covers it.
    WhileFound,
    /// An advisory: kept as [`Hold::WhileFound`] is, shown on its own line,
    /// never a degradation (`sensors`, the trust level, the manifest).
    Advisory,
    /// Not held: shown by its own degradation, or no finding.
    NotHeld,
}

/// How a kind in no table is held: as a degradation (a row of another
/// build; the product's own kinds are all classified — the ratchet).
pub const UNKNOWN_KIND: Hold = Hold::WhileFound;

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

/// Lot 379 (pre-alpha Phase 7b, F7-6): the deaths of the agent's and the
/// watchdog's roles — an event no later state undoes, and the restart it
/// causes is the next start: held until an acknowledgement covers them, like
/// the evidence. The witness's findings (nn-linux `witness`: the agent's role
/// vacated — a crash, a kill, an OOM —, a successor not its unit's clean
/// restart, both roles found vacated, a row only the watchdog's own claim
/// vouches for) and the round's `watchdog_gone` (the verified watchdog no
/// longer runs). Its bookkeeping (a key certified, a clean succession, a
/// release in a window) is signed as a note, never held.
pub const DEATH_KINDS: &[&str] = &[
    "witness_row",
    "witness_row_uncertified",
    "roles_vacated_gap",
    "watchdog_successor_foreign",
    "watchdog_successor_unconfirmed",
    "watchdog_gone",
];

/// The review of #586 (P3-2): the attack-class events of the run — nothing
/// checks them again at a start (they are events, not states), so a start,
/// a host reboot included, ends nothing: held until an acknowledgement
/// covers them, like a death.
pub const EVENT_KINDS: &[&str] = &[
    // External audit WDG-001: a shutdown marker the watchdog refused
    // (forged, replayed or stale)
    "shutdown_marker_rejected",
    // the agent's admin socket removed while it ran
    "admin_socket_removed",
    // External audit ASK-012: a peer the admin socket refused
    "admin_socket_foreign_peer",
];

/// The degradations held while found ([`Hold::WhileFound`]): a state of the
/// host or of the agent that weakens what it sees or defends, checked again
/// by the round that signed it (its `cleared`) or by the next start.
pub const DEGRADATION_KINDS: &[&str] = &[
    // the overlays and the default lists (F7-1, F3b-6)
    "config_overlay",
    "unauthorized_overlay",
    "default_list_modified",
    "default_list_unavailable",
    // the agent's settings weakened (its environment, its flags)
    "weakening_env",
    "weakening_flag",
    // systemd's units, our drop-ins and the host's
    "unit_dropin",
    "unit_shadowed",
    "unit_dropin_breaks_agent",
    "own_dropin_weakening",
    "own_dropin_moved",
    "own_dropin_not_moved",
    "own_dropin_preinstall_harmful",
    "own_dropin_round_skipped",
    // the resource limits of our units
    "limit_unexpected",
    "limit_appeared",
    "limit_removed",
    "limit_changed",
    "limit_floor_restored",
    "limit_floor_not_restored",
    "systemd_copy_below_floor",
    // the mounts over or around the agent's paths
    "mount_over_protected",
    "mount_not_canonical",
    "mount_attrs_changed",
    "protected_mount_gone",
    "mountinfo_unreadable",
    "state_fs_read_only",
    "bpffs_mount",
    "tracefs_mount",
    // the pins of the agent's kernel objects
    "bpf_pin_vanished",
    "foreign_pin",
    // the guarded sysctls: a harmful value set, restored or not
    "sysctl_restored",
    "sysctl_not_restored",
    // the decoys and the baits touched
    "canary_decoy_missing",
    "canary_decoy_tampered",
    "bait_missing_at_boot",
    // COMBAT's isolation not reconciled at the start
    "combat_reconcile",
    // the watchdog's holds (its record of what it found or did)
    "admin_socket_vanished",
    "respawn_argv_degraded",
    "watchdog_exit",
    "watchdog_failed",
    "stuck_recovery_failed",
    "event_loop_stalled",
    "stuck_unresponsive",
    "fuse_aborted",
    "signed_records_failed",
    "watchdog_start_refused",
    "witness_unavailable",
    "watchdog_hold",
    "watchdog_respawn_held",
    // the review of #586 (P2-2): a bookkeeping row of the witness whose key
    // no live watchdog vouched for (its claim alone; not a death)
    "witness_note_uncertified",
];

/// The advisories ([`Hold::Advisory`]): shown by `nn-admin status` on their
/// own, with their signed row, kept as a degradation is — never counted in
/// `sensors`, the trust level or the manifest's degradations — and why.
pub const ADVISORY_KINDS: &[(&str, &str)] = &[
    (
        "admin_key_on_host",
        "the host's hardening (the alpha tester guide's WARN): no sensor is degraded",
    ),
    (
        "sysctl_strict",
        "strict overcommit with a high ratio (a database's tuning): a host setting, not the agent's",
    ),
    (
        "sysctl_opted_out",
        "the operator's own signed opt-out of a guarded sysctl",
    ),
    (
        "agent_stalled",
        "the agent's loop stood still (a VM pause, a host suspend, the kernel holding the agent back \
         above its own MemoryHigh): nothing it guards changed; a loss it caused is counted on its own",
    ),
    (
        "quarantine_index_rebuilt",
        "a repair note: the quarantine's index rebuilt from its files",
    ),
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
    (
        "unit_dropin_harmful",
        "the host_dropins degradation (lot 273d) shows it while it holds, withdrawn when it ends",
    ),
    (
        "own_dropin_setting",
        "an NN_ setting of a kept drop-in of ours, signed `recorded`: no drift",
    ),
    (
        "legacy_isolation_removed",
        "a repair at the start, signed `repaired`",
    ),
];

/// How a signed `integrity_drift` row of `kind` with `result` is held.
pub fn hold_of(kind: &str, result: &str) -> Hold {
    if !matches!(result, "detected" | "failed") {
        return Hold::NotHeld;
    }
    if NOT_HELD_KINDS.iter().any(|(k, _)| *k == kind) {
        Hold::NotHeld
    } else if EVIDENCE_KINDS.contains(&kind)
        || DEATH_KINDS.contains(&kind)
        || EVENT_KINDS.contains(&kind)
    {
        Hold::UntilAcknowledged
    } else if ADVISORY_KINDS.iter().any(|(k, _)| *k == kind) {
        Hold::Advisory
    } else if DEGRADATION_KINDS.contains(&kind) {
        Hold::WhileFound
    } else {
        UNKNOWN_KIND
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
            Hold::Advisory => "an advisory, not a degradation: shown while found",
            _ => "held while found, or until acknowledged",
        };
        format!("{}{about} — {times} — {until}: {}", self.kind, self.detail)
    }
}

/// The held findings of one chain, as its rows say.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Held {
    findings: Vec<HeldFinding>,
    /// Rows of findings past [`MAX_HELD`] (counted, and the newest row) of
    /// each class ([`class`]).
    more: [(u64, u64); 3],
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

/// The counter of a class past the cap: 0 held until acknowledged, 1 a
/// degradation while found, 2 an advisory.
fn class(hold: Hold) -> usize {
    match hold {
        Hold::UntilAcknowledged => 0,
        Hold::Advisory => 2,
        _ => 1,
    }
}

/// The path of an overlay finding: `config_overlay`'s detail starts with
/// it, `unauthorized_overlay`'s names it in parentheses after its keyword.
fn overlay_path(f: &HeldFinding) -> Option<&str> {
    match f.kind.as_str() {
        "config_overlay" => f.detail.split(" (").next(),
        "unauthorized_overlay" => f
            .detail
            .split_once(" (")
            .and_then(|(_, rest)| rest.split_once("): "))
            .map(|(path, _)| path),
        _ => None,
    }
}

impl Held {
    /// The findings held, oldest first.
    pub fn findings(&self) -> &[HeldFinding] {
        &self.findings
    }

    /// Rows of degradations held past [`MAX_HELD`], not listed.
    pub fn more(&self) -> u64 {
        self.more[0].0 + self.more[1].0
    }

    /// Every finding held, listed or counted, advisories included (what an
    /// acknowledgement can cover).
    pub fn count(&self) -> u64 {
        self.findings.len() as u64 + self.more.iter().map(|m| m.0).sum::<u64>()
    }

    /// Nothing held, advisories included.
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty() && self.more() == 0 && self.more[2].0 == 0
    }

    /// The degradations `nn-admin status` lists: one a finding, then one
    /// counting those not listed. The review of #586 (P2-1): an advisory is
    /// not among them ([`Held::advisories`]); a `config_overlay` whose file
    /// a held `unauthorized_overlay` names is that line's (one fact, one
    /// line, which names both rows).
    pub fn lines(&self) -> Vec<String> {
        let twin = |f: &HeldFinding| {
            let path = overlay_path(f)?;
            self.findings
                .iter()
                .find(|g| g.kind == "config_overlay" && overlay_path(g) == Some(path))
        };
        let refused: Vec<&str> = self
            .findings
            .iter()
            .filter(|f| f.kind == "unauthorized_overlay")
            .filter_map(overlay_path)
            .collect();
        let mut out: Vec<String> = self
            .findings
            .iter()
            .filter(|f| f.hold != Hold::Advisory)
            .filter(|f| {
                f.kind != "config_overlay" || !overlay_path(f).is_some_and(|p| refused.contains(&p))
            })
            .map(
                |f| match twin(f).filter(|_| f.kind == "unauthorized_overlay") {
                    Some(g) => format!(
                    "{} — the integrity round signs the same file as config_overlay (audit row {})",
                    f.line(),
                    g.last_row
                ),
                    None => f.line(),
                },
            )
            .collect();
        if self.more() > 0 {
            out.push(format!(
                "… and {} more held integrity row(s) (in the signed audit log)",
                self.more()
            ));
        }
        out
    }

    /// The review of #586 (P2-1): the advisories `nn-admin status` lists on
    /// their own — a state of the host or a choice of the operator, signed,
    /// that degrades no sensor.
    pub fn advisories(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .findings
            .iter()
            .filter(|f| f.hold == Hold::Advisory)
            .map(HeldFinding::line)
            .collect();
        if self.more[2].0 > 0 {
            out.push(format!(
                "… and {} more advisory row(s) (in the signed audit log)",
                self.more[2].0
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
                let ends = |f: &HeldFinding| {
                    f.hold != Hold::UntilAcknowledged && f.kind == kind && f.subject == subject
                };
                if !self.findings.iter().any(ends) || !genuine(entry) {
                    return false;
                }
                self.findings.retain(|f| !ends(f));
                true
            }
            // a start checks again: what it still finds, it signs again
            "agent_boot" if entry.result == "success" => {
                let found = self
                    .findings
                    .iter()
                    .any(|f| f.hold != Hold::UntilAcknowledged)
                    || self.more[1].0 > 0
                    || self.more[2].0 > 0;
                if !found || !genuine(entry) {
                    return false;
                }
                self.findings.retain(|f| f.hold == Hold::UntilAcknowledged);
                self.more[1] = (0, 0);
                self.more[2] = (0, 0);
                true
            }
            ACK_OP if entry.result == "success" => {
                let Some(through) = entry.extra.get("through_row").and_then(|v| v.as_u64()) else {
                    return false;
                };
                // it covers only rows already observed, all before its own
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
        // the review of #586 (P3-4): every part of a held line is bounded
        let kind = cut(kind);
        let kind = kind.as_str();
        let detail = cut(text(&entry.extra, "detail").unwrap_or(""));
        let subject = text(&entry.extra, "chain")
            .map(cut)
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
            return true;
        }
        if self.findings.len() >= MAX_HELD {
            // the review of #586 (P3-3): a finding held until acknowledged
            // is listed — its kind, its row, the command that ends it —
            // before one that a start ends: the newest of those is counted
            // in its stead
            let demoted = (hold == Hold::UntilAcknowledged)
                .then(|| {
                    self.findings
                        .iter()
                        .rposition(|f| f.hold != Hold::UntilAcknowledged)
                })
                .flatten();
            let Some(i) = demoted else {
                let m = &mut self.more[class(hold)];
                m.0 += 1;
                m.1 = row;
                return true;
            };
            let f = self.findings.remove(i);
            let m = &mut self.more[class(f.hold)];
            m.0 += f.rows;
            m.1 = m.1.max(f.last_row);
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
