//! Lab PR 221 (capability C16): the MITRE ATT&CK® mapping of every rule,
//! as data.
//!
//! Each [`Rule`](super::Rule) declares the tactics and the techniques or
//! sub-techniques it is evidence of ([`Rule::attack`](super::Rule::attack)),
//! as [`AttackRef`]s: a [`Tactic`] (an enum of the Enterprise tactics) and a
//! [`TechniqueId`], a technique id whose shape is checked when the constant
//! is compiled. A detection record carries them in its `mitre` field
//! ([`mitre_of`]), with the ATT&CK version they are ids of.
//!
//! The ids are those of ATT&CK Enterprise [`ATTACK_VERSION`]. Version 19
//! (2026-04-28) renamed TA0005 Defense Evasion to Stealth, added TA0112
//! Defense Impairment and revoked the Impair Defenses family (T1562 and its
//! sub-techniques; their behaviours are now T1685 Disable or Modify Tools
//! and its siblings), so an id is meaningful only with its version. The ids
//! the rules use, and the revoked ones they used to name in prose, are
//! pinned with their v20 names, tactics and status in [`ATTACK_IDS_FILE`],
//! extracted from MITRE's STIX bundle (the file's header gives the commit
//! and the sha256); the tests below hold every mapping to it. ATT&CK
//! content is MITRE's, under its Terms of Use (`NOTICES.md`).

use crate::detection_payload::MitreAttack;

/// The ATT&CK domain the mapping is in.
pub const ATTACK_DOMAIN: &str = "enterprise-attack";

/// The ATT&CK Enterprise version the ids are from (`x_mitre_version` of the
/// pinned collection). A detection record carries it next to the ids.
pub const ATTACK_VERSION: &str = "20.0";

/// The pinned list of the ATT&CK ids the mapping may use, relative to the
/// repository root.
pub const ATTACK_IDS_FILE: &str = "docs/detection/attack-enterprise-20.0.tsv";

/// An ATT&CK Enterprise tactic, in the order of the Enterprise matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tactic {
    Reconnaissance,
    ResourceDevelopment,
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    /// TA0005: "Defense Evasion" until v19.
    Stealth,
    /// TA0112, new in v19.
    DefenseImpairment,
    CredentialAccess,
    Discovery,
    LateralMovement,
    Collection,
    CommandAndControl,
    Exfiltration,
    Impact,
}

impl Tactic {
    /// Every tactic, in matrix order.
    pub const ALL: [Tactic; 15] = [
        Tactic::Reconnaissance,
        Tactic::ResourceDevelopment,
        Tactic::InitialAccess,
        Tactic::Execution,
        Tactic::Persistence,
        Tactic::PrivilegeEscalation,
        Tactic::Stealth,
        Tactic::DefenseImpairment,
        Tactic::CredentialAccess,
        Tactic::Discovery,
        Tactic::LateralMovement,
        Tactic::Collection,
        Tactic::CommandAndControl,
        Tactic::Exfiltration,
        Tactic::Impact,
    ];

    /// The tactic's ATT&CK id (`TA0005`).
    pub const fn id(self) -> &'static str {
        match self {
            Tactic::Reconnaissance => "TA0043",
            Tactic::ResourceDevelopment => "TA0042",
            Tactic::InitialAccess => "TA0001",
            Tactic::Execution => "TA0002",
            Tactic::Persistence => "TA0003",
            Tactic::PrivilegeEscalation => "TA0004",
            Tactic::Stealth => "TA0005",
            Tactic::DefenseImpairment => "TA0112",
            Tactic::CredentialAccess => "TA0006",
            Tactic::Discovery => "TA0007",
            Tactic::LateralMovement => "TA0008",
            Tactic::Collection => "TA0009",
            Tactic::CommandAndControl => "TA0011",
            Tactic::Exfiltration => "TA0010",
            Tactic::Impact => "TA0040",
        }
    }

    /// The tactic's short name (`x_mitre_shortname`, the kill-chain phase
    /// a technique names and an ATT&CK Navigator layer uses).
    pub const fn shortname(self) -> &'static str {
        match self {
            Tactic::Reconnaissance => "reconnaissance",
            Tactic::ResourceDevelopment => "resource-development",
            Tactic::InitialAccess => "initial-access",
            Tactic::Execution => "execution",
            Tactic::Persistence => "persistence",
            Tactic::PrivilegeEscalation => "privilege-escalation",
            Tactic::Stealth => "stealth",
            Tactic::DefenseImpairment => "defense-impairment",
            Tactic::CredentialAccess => "credential-access",
            Tactic::Discovery => "discovery",
            Tactic::LateralMovement => "lateral-movement",
            Tactic::Collection => "collection",
            Tactic::CommandAndControl => "command-and-control",
            Tactic::Exfiltration => "exfiltration",
            Tactic::Impact => "impact",
        }
    }

    /// The tactic's ATT&CK name.
    pub const fn name(self) -> &'static str {
        match self {
            Tactic::Reconnaissance => "Reconnaissance",
            Tactic::ResourceDevelopment => "Resource Development",
            Tactic::InitialAccess => "Initial Access",
            Tactic::Execution => "Execution",
            Tactic::Persistence => "Persistence",
            Tactic::PrivilegeEscalation => "Privilege Escalation",
            Tactic::Stealth => "Stealth",
            Tactic::DefenseImpairment => "Defense Impairment",
            Tactic::CredentialAccess => "Credential Access",
            Tactic::Discovery => "Discovery",
            Tactic::LateralMovement => "Lateral Movement",
            Tactic::Collection => "Collection",
            Tactic::CommandAndControl => "Command and Control",
            Tactic::Exfiltration => "Exfiltration",
            Tactic::Impact => "Impact",
        }
    }
}

/// An ATT&CK technique (`T1053`) or sub-technique (`T1053.003`) id. Its
/// shape is checked by [`TechniqueId::new`], at compile time in a
/// constant; whether the id exists, and is not revoked or deprecated, in
/// the pinned version is checked by the tests against [`ATTACK_IDS_FILE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TechniqueId(&'static str);

impl TechniqueId {
    /// `id`, which must read `T` and four digits, optionally followed by
    /// `.` and three digits. In a `const` item a malformed id is a
    /// compile error.
    pub const fn new(id: &'static str) -> Self {
        assert!(
            well_formed(id.as_bytes()),
            "ATT&CK technique id: T#### or T####.###"
        );
        TechniqueId(id)
    }

    /// The id (`T1053.003`).
    pub const fn as_str(self) -> &'static str {
        self.0
    }

    /// `true` for a sub-technique (`T1053.003`).
    pub const fn is_subtechnique(self) -> bool {
        self.0.len() == 9
    }

    /// The parent technique's id (`T1053` for `T1053.003`; the id itself
    /// for a technique).
    pub fn parent(self) -> &'static str {
        &self.0[..5]
    }
}

impl std::fmt::Display for TechniqueId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

const fn well_formed(b: &[u8]) -> bool {
    if !(b.len() == 5 || b.len() == 9) || b[0] != b'T' {
        return false;
    }
    let mut i = 1;
    while i < b.len() {
        let ok = if i == 5 {
            b[i] == b'.'
        } else {
            b[i].is_ascii_digit()
        };
        if !ok {
            return false;
        }
        i += 1;
    }
    true
}

/// One ATT&CK reference of a rule: a technique and the tactic, among the
/// technique's tactics, that the rule's detection is evidence of. A rule
/// that is evidence of a technique under two tactics (a cron drop-in is
/// persistence and privilege escalation) carries two references.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttackRef {
    pub tactic: Tactic,
    pub technique: TechniqueId,
}

impl AttackRef {
    /// `technique` under `tactic`. In a `const` item a malformed id is a
    /// compile error ([`TechniqueId::new`]).
    pub const fn new(tactic: Tactic, technique: &'static str) -> Self {
        AttackRef {
            tactic,
            technique: TechniqueId::new(technique),
        }
    }
}

/// The `mitre` field of a detection record for a rule's references: the
/// tactic ids, then the technique ids, each once, in the order the rule
/// declares them (the shape of the advisor's records before Wave 4, lab
/// PR 214, which still verify).
pub fn mitre_of(refs: &[AttackRef]) -> MitreAttack {
    let mut tactic: Vec<String> = Vec::new();
    let mut technique: Vec<String> = Vec::new();
    for r in refs {
        if !tactic.iter().any(|t| t == r.tactic.id()) {
            tactic.push(r.tactic.id().to_string());
        }
        if !technique.iter().any(|t| t == r.technique.as_str()) {
            technique.push(r.technique.as_str().to_string());
        }
    }
    MitreAttack { tactic, technique }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn technique_ids_are_checked_for_shape() {
        assert!(well_formed(b"T1053"));
        assert!(well_formed(b"T1053.003"));
        for bad in [
            "",
            "T",
            "T105",
            "T10533",
            "T1053.",
            "T1053.03",
            "T1053.0033",
            "t1053",
            "TA0005",
            "T1053-003",
            "T10a3",
            "T1053.0a3",
        ] {
            assert!(!well_formed(bad.as_bytes()), "{bad}");
        }
        let t = TechniqueId::new("T1053.003");
        assert!(t.is_subtechnique());
        assert_eq!(t.parent(), "T1053");
        assert!(!TechniqueId::new("T1611").is_subtechnique());
        assert_eq!(TechniqueId::new("T1611").parent(), "T1611");
    }

    #[test]
    #[should_panic(expected = "ATT&CK technique id")]
    fn a_malformed_technique_id_is_refused() {
        let id = String::from("T1562.1");
        let _ = TechniqueId::new(Box::leak(id.into_boxed_str()));
    }

    #[test]
    fn mitre_of_lists_each_id_once_in_declaration_order() {
        const REFS: &[AttackRef] = &[
            AttackRef::new(Tactic::Persistence, "T1053.003"),
            AttackRef::new(Tactic::PrivilegeEscalation, "T1053.003"),
            AttackRef::new(Tactic::Execution, "T1059.004"),
        ];
        let m = mitre_of(REFS);
        assert_eq!(m.tactic, ["TA0003", "TA0004", "TA0002"]);
        assert_eq!(m.technique, ["T1053.003", "T1059.004"]);
        let empty = mitre_of(&[]);
        assert!(empty.tactic.is_empty() && empty.technique.is_empty());
    }

    #[test]
    fn tactics_are_in_matrix_order_with_distinct_ids() {
        let mut ids: Vec<&str> = Tactic::ALL.iter().map(|t| t.id()).collect();
        let mut sorted = Tactic::ALL.to_vec();
        sorted.sort();
        assert_eq!(sorted, Tactic::ALL.to_vec(), "ALL follows the enum order");
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), Tactic::ALL.len());
    }
}
