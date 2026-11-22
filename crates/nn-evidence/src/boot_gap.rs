//! Lot 387 (pre-alpha Phase 3d, F3d-1): the boots between the agent's last
//! run and this start.
//!
//! Root can keep the agent from starting at boot — a generator that masks
//! its units, `systemd.mask=` on the kernel command line, a default target
//! without it — and the host records none of these writes. After the
//! restore, the first start signed `previous_run: {ended: clean, reason:
//! system_shutdown}`: a clean run end followed by whole boots without the
//! agent was told as a clean succession.
//!
//! Each start now judges the boots in between ([`judge`]): the boot of the
//! last run (the `boot_id` of its signed `agent_boot` row; for a chain of an
//! agent before the field, the state directory's `last_boot_id`) against
//! this boot's, and when they differ, both against the journal's boot list
//! (`journalctl --list-boots`, oldest first). A boot listed between them had
//! no run of the agent: [`BootContinuity::BootsWithoutAgent`], signed High
//! and held until an operator acknowledges it. When the facts cannot be
//! read — a volatile journal keeps only this boot, the previous one was
//! rotated or removed, the list did not answer — the start says
//! [`BootContinuity::Unknown`], never clean.
//!
//! Every source but this boot's id is one root can rewrite before the agent
//! starts: the audit chain (its key is readable before the agent runs —
//! KNOWN_LIMITATIONS, R016), the state file, the journal. The record is a
//! statement of what the agent could read, not proof; the witness that
//! root on the host cannot rewrite is the external heartbeat verifier
//! (`NOT_BACK`).

/// The `integrity_drift` kind of one or more boots without a run of the
/// agent between its last run and this start (High; held until an
/// acknowledgement covers it, like a death of the agent's role).
pub const BOOTS_WITHOUT_AGENT_KIND: &str = "boots_without_agent";

/// The `integrity_drift` kind of a start that cannot tell whether boots
/// passed without the agent (an advisory: shown, never counted as a
/// degradation).
pub const BOOT_CONTINUITY_UNKNOWN_KIND: &str = "boot_continuity_unknown";

/// Boot ids listed in a row at most; past it they are counted.
pub const LISTED_BOOT_IDS_MAX: usize = 16;

/// The sources a judgement reads, and who can rewrite them — signed in
/// every row that tells a gap or an unknown.
pub const SOURCES: &[(&str, &str)] = &[
    (
        "this boot's id (/proc/sys/kernel/random/boot_id)",
        "the kernel's, read-only",
    ),
    (
        "the last run's boot id (its signed agent_boot row; the state file last_boot_id for a row \
         before the field)",
        "root can rewrite both before the agent starts (the signing key is readable then, R016)",
    ),
    (
        "the journal's boot list (journalctl --list-boots)",
        "root can remove, vacuum or rotate it, or make the journal volatile",
    ),
];

/// What the host did between the agent's last run and this start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootContinuity {
    /// No earlier run in the chain: nothing to judge.
    FirstRun,
    /// This start runs in the last run's boot: a restart.
    SameBoot,
    /// This boot directly follows the last run's in the journal's list.
    NextBoot,
    /// `count` boots between the last run's and this one had no run of the
    /// agent; the first [`LISTED_BOOT_IDS_MAX`] of their ids, oldest first.
    BootsWithoutAgent { count: u64, boot_ids: Vec<String> },
    /// Not knowable at this start, and why.
    Unknown { why: String },
}

impl BootContinuity {
    /// The word of the judgement (`state` in the signed rows).
    pub fn label(&self) -> &'static str {
        match self {
            BootContinuity::FirstRun => "first_run",
            BootContinuity::SameBoot => "same_boot",
            BootContinuity::NextBoot => "next_boot",
            BootContinuity::BootsWithoutAgent { .. } => BOOTS_WITHOUT_AGENT_KIND,
            BootContinuity::Unknown { .. } => "unknown",
        }
    }

    /// Whether nothing is known to have passed between the last run and
    /// this start: only then may a clean end of that run be told `clean`.
    pub fn continuous(&self) -> bool {
        matches!(
            self,
            BootContinuity::FirstRun | BootContinuity::SameBoot | BootContinuity::NextBoot
        )
    }

    /// The judgement as the `agent_boot` row's `previous_run.boots_since`.
    pub fn to_json(&self) -> serde_json::Value {
        let mut v = serde_json::json!({ "state": self.label() });
        match self {
            BootContinuity::BootsWithoutAgent { count, boot_ids } => {
                v["count"] = (*count).into();
                v["boot_ids"] = boot_ids.clone().into();
            }
            BootContinuity::Unknown { why } => v["why"] = why.clone().into(),
            _ => {}
        }
        v
    }
}

/// The sources ([`SOURCES`]) as the rows sign them.
pub fn sources_json() -> serde_json::Value {
    SOURCES
        .iter()
        .map(|(s, w)| serde_json::json!({ "source": s, "rewritable": w }))
        .collect::<Vec<_>>()
        .into()
}

/// A boot id as one form: 32 lowercase hex digits (the kernel writes it
/// with dashes, the journal without). `None`: not a boot id.
pub fn normalize(id: &str) -> Option<String> {
    let s: String = id
        .trim()
        .chars()
        .filter(|c| *c != '-')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    (s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())).then_some(s)
}

/// The boot ids of `journalctl --list-boots`'s text, in its order (oldest
/// first): on each line, the first word that is a boot id. A header, a
/// note or an empty answer gives none.
pub fn parse_list_boots(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.split_whitespace().find_map(normalize))
        .collect()
}

/// What a start knows when it judges.
#[derive(Debug, Clone, Copy)]
pub struct BootFacts<'a> {
    /// The chain holds an earlier run (`previous_run` not `none`).
    pub previous_run: bool,
    /// The boot id of that run, when recorded.
    pub previous_boot: Option<&'a str>,
    /// This boot's id, when readable.
    pub current_boot: Option<&'a str>,
}

/// Judge the boots between the last run and this start. `list_boots`
/// gives the journal's boot ids, oldest first — asked only when the boot
/// changed.
pub fn judge(
    facts: BootFacts<'_>,
    list_boots: impl FnOnce() -> Result<Vec<String>, String>,
) -> BootContinuity {
    let unknown = |why: String| BootContinuity::Unknown { why };
    if !facts.previous_run {
        return BootContinuity::FirstRun;
    }
    let Some(current) = facts.current_boot.and_then(normalize) else {
        return unknown("this boot's id could not be read".into());
    };
    let Some(previous) = facts.previous_boot.and_then(normalize) else {
        return unknown(
            "the last run's boot is not recorded (no boot id in its agent_boot row, no state file)"
                .into(),
        );
    };
    if previous == current {
        return BootContinuity::SameBoot;
    }
    let boots = match list_boots() {
        Ok(b) => b,
        Err(why) => return unknown(format!("the journal's boot list could not be read: {why}")),
    };
    let boots: Vec<String> = boots.iter().filter_map(|b| normalize(b)).collect();
    let Some(at_current) = boots.iter().rposition(|b| *b == current) else {
        return unknown(format!(
            "this boot is not in the journal's boot list ({} boot(s) listed)",
            boots.len()
        ));
    };
    // the widest window, the safe side: from the first listing of the last
    // run's boot to the last listing of this one (a boot listed twice — its
    // entries split by another's — counts what lies between its parts)
    let Some(at_previous) = boots.iter().position(|b| *b == previous) else {
        return unknown(format!(
            "the last run's boot {previous} is not in the journal's boot list ({} boot(s) kept: \
             a volatile journal, or the older boots rotated or removed)",
            boots.len()
        ));
    };
    if at_previous > at_current {
        return unknown(format!(
            "the journal lists the last run's boot {previous} after this one"
        ));
    }
    // this boot is the newest the journal can know: boots listed after it
    // mean an order not to be trusted (a clock set back, a list rewritten)
    if at_current + 1 != boots.len() {
        return unknown(format!(
            "the journal lists {} boot(s) after this one",
            boots.len() - at_current - 1
        ));
    }
    let mut between: Vec<&String> = Vec::new();
    for b in &boots[at_previous + 1..at_current] {
        if *b != previous && *b != current && !between.contains(&b) {
            between.push(b);
        }
    }
    if between.is_empty() {
        return BootContinuity::NextBoot;
    }
    BootContinuity::BootsWithoutAgent {
        count: between.len() as u64,
        boot_ids: between
            .into_iter()
            .take(LISTED_BOOT_IDS_MAX)
            .cloned()
            .collect(),
    }
}

#[cfg(test)]
mod tests;
