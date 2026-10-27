//! Lab PR 221 (capability C16): what each rule is, as data — the source of
//! `docs/detection/RULE_CATALOGUE.md`, `docs/detection/ATTACK_COVERAGE.md`
//! and the ATT&CK Navigator layer (`cargo xtask attack-coverage`).
//!
//! One [`RuleDoc`] per rule the agent can record. Its ATT&CK references
//! are not here: each rule declares them itself ([`Rule::attack`]); this
//! table holds what a reader of the catalogue needs besides — the
//! severities and responses the rule can issue, the sensors it reads, what
//! it observes, its known false positives and how to exercise it. The
//! tests hold the table to the rule set: one entry per shipped rule, in no
//! other order than the rule's family, every cited test present.
//!
//! [`Rule::attack`]: super::Rule::attack

use nn_model::{ResponseAction, Severity};

use crate::detection_payload::Sensor;

mod fim;
mod net;
mod other;
mod process;

/// What the catalogue says about one rule.
#[derive(Debug)]
pub struct RuleDoc {
    /// The rule's id ([`Rule::id`](super::Rule::id)).
    pub id: &'static str,
    /// The severities the rule can issue, the highest first.
    pub severities: &'static [Severity],
    /// The responses it can ask for, the strongest first ([`ResponseAction::Log`]
    /// for a rule that only records).
    pub actions: &'static [ResponseAction],
    /// The sensors whose events it reads, the one its record names
    /// ([`Sensor::from_event`]) first.
    pub sensors: &'static [Sensor],
    /// The ATT&CK data components (`DC0032`) the events it reads are
    /// instances of, ids of [`super::attack::ATTACK_IDS_FILE`].
    pub data_components: &'static [&'static str],
    /// What it observes, in one or two sentences.
    pub observes: &'static str,
    /// Its known false positives and the carve-outs that answer them.
    pub false_positives: &'static str,
    /// How to make it fire on a lab guest.
    pub how_to_test: &'static str,
    /// The tests that fire it: `path::function` (a Rust test) or
    /// `path::text` (a lab probe that contains `text`), relative to the
    /// repository root.
    pub tests: &'static [&'static str],
    /// What the ATT&CK mapping does not say by itself: why a technique was
    /// chosen, what the rule does not cover. Empty when nothing.
    pub attack_note: &'static str,
}

/// The four families of the table, in the order of the catalogue.
pub const FAMILIES: [(&str, &[RuleDoc]); 4] = [
    ("Process", process::DOCS),
    ("File integrity and file access", fim::DOCS),
    ("Network", net::DOCS),
    (
        "Canary, chain, io_uring, BPF, anti-tamper, exploit guard and security tools",
        other::DOCS,
    ),
];

/// Every entry, family by family.
pub fn docs() -> impl Iterator<Item = &'static RuleDoc> {
    FAMILIES.iter().flat_map(|(_, d)| d.iter())
}

/// The entry of `rule_id`.
pub fn doc(rule_id: &str) -> Option<&'static RuleDoc> {
    docs().find(|d| d.id == rule_id)
}
