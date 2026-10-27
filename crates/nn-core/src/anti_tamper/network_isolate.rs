//! The COMBAT isolation's read-back vocabulary (lab PR 217, capability
//! C18): an IP family, and what an engage or a release of the isolation
//! found in that family's table, read back after it ran.
//!
//! R08c (lab PR 252): cut verbatim from the agent's
//! `anti_tamper::network_isolate`, which re-exports them and keeps the
//! isolator — `iptables-restore` and its read-back, the management
//! carve-out, the release that takes the unlock token — for nn-linux (R09).
//! The COMBAT ladder, which moves to nn-core, records an ISOLATE's outcome
//! per family and retries a family that failed (`IsolateOutcome`).

/// An IP family COMBAT isolates (lab PR 217: the state is kept per family).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub fn label(self) -> &'static str {
        match self {
            Family::V4 => "IPv4",
            Family::V6 => "IPv6",
        }
    }
}

/// What an engage or a release found in one family's table, read back
/// (lab PR 217).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FamilyOutcome {
    /// Engage: the table holds the COMBAT chain, its catch-all DROP and
    /// every jump into it. Release: it holds neither the chain nor a jump.
    Done,
    /// Nothing of COMBAT can be applied or read in this family, and none of
    /// ours is known to be there: no v6 ruleset provisioned (a build without
    /// the overlay gate), no trusted `ip6tables` on the host, a table the
    /// kernel does not have. Permanent — a retry would not change it — and
    /// named in the record: after an engage it is a hole (that family's
    /// traffic is not dropped).
    Unavailable(String),
    /// The step did not take effect; the reason, from the read-back.
    Failed(String),
}

impl FamilyOutcome {
    /// `done`, `unavailable: …`, `FAILED: …` — for a structured record.
    pub fn describe_short(&self) -> String {
        match self {
            FamilyOutcome::Done => "done".to_string(),
            FamilyOutcome::Unavailable(why) => format!("unavailable: {why}"),
            FamilyOutcome::Failed(why) => format!("FAILED: {why}"),
        }
    }

    fn describe(&self, family: Family, done: &str) -> String {
        match self {
            FamilyOutcome::Done => format!("{}: {done}", family.label()),
            FamilyOutcome::Unavailable(why) => format!("{}: unavailable ({why})", family.label()),
            FamilyOutcome::Failed(why) => format!("{}: FAILED ({why})", family.label()),
        }
    }
}

/// The outcome of `NetworkIsolator::engage` or `NetworkIsolator::release`
/// per IP family, as the tables were read back (lab PR 217).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IsolationReport {
    pub v4: FamilyOutcome,
    pub v6: FamilyOutcome,
}

impl IsolationReport {
    /// Engage: the critical (IPv4) leg is in place — the host is isolated.
    pub fn engaged(&self) -> bool {
        self.v4 == FamilyOutcome::Done
    }

    /// No family failed: an engage that isolated every family that can be
    /// isolated on this host, a release that left every table clear. A
    /// failed family is worth a retry; an unavailable one is not.
    pub fn complete(&self) -> bool {
        !matches!(self.v4, FamilyOutcome::Failed(_)) && !matches!(self.v6, FamilyOutcome::Failed(_))
    }

    /// One line per report, for the journal, the signed record and the
    /// admin reply. `done` names what [`FamilyOutcome::Done`] means.
    pub fn summary(&self, done: &str) -> String {
        format!(
            "{}; {}",
            self.v4.describe(Family::V4, done),
            self.v6.describe(Family::V6, done)
        )
    }
}
