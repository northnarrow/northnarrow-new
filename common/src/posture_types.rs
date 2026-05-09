//! Adaptive Defensive Posture types (Sub-tappa 6.5).
//!
//! These structs are the serializable, on-the-wire portion of the
//! posture state machine. The agent crate keeps a richer runtime
//! representation around (with `std::time::Instant` timestamps and
//! `RwLock`s); these types are what cross logging, audit and future
//! C2 boundaries.
//!
//! Design rules:
//!
//! - `PostureKind` is a flat enum, ordered by gravity. Comparison is
//!   meaningful (`PostureKind::Observing < PostureKind::Combat`).
//! - `TriggerType` enumerates every condition that can drive a
//!   transition. New triggers append at the end (stable
//!   serialization).
//! - `PostureTransition` is the audit record: it captures the
//!   from/to states, the firing trigger (or `None` for decay), a
//!   wall-clock unix timestamp, and a short reason string.

use alloc::string::String;
use serde::{Deserialize, Serialize};

/// Defensive posture levels, ordered by gravity (Observing < Combat).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PostureKind {
    /// Baseline. No suspicious correlation observed.
    Observing,
    /// Reconnaissance / recon-adjacent signals seen.
    Alerted,
    /// Active exploitation or critical file mutation observed.
    Engaged,
    /// Confirmed compromise. No automatic exit.
    Combat,
}

impl PostureKind {
    /// Canonical PascalCase rendering used in logs and on the wire.
    pub fn as_str(&self) -> &'static str {
        match self {
            PostureKind::Observing => "OBSERVING",
            PostureKind::Alerted => "ALERTED",
            PostureKind::Engaged => "ENGAGED",
            PostureKind::Combat => "COMBAT",
        }
    }
}

impl core::fmt::Display for PostureKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Triggers that can drive an upward posture transition.
///
/// The variant ordering tracks the level of escalation a trigger
/// produces (recon < exploit < intrusion). New entries append.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TriggerType {
    // OBSERVING -> ALERTED
    Reconnaissance,
    SuspiciousDns,
    SensitiveFileAccess,
    Lolbas,

    // ALERTED -> ENGAGED
    ExploitAttempt,
    AdjacentCompromise,
    HeavyReconnaissance,
    CriticalFileModification,

    // ENGAGED -> COMBAT
    ConfirmedIntrusion,
    PersistenceMechanism,
    LateralMovement,
    ExfiltrationPattern,
}

impl TriggerType {
    /// Highest posture level this trigger can promote to.
    pub fn target_level(&self) -> PostureKind {
        match self {
            TriggerType::Reconnaissance
            | TriggerType::SuspiciousDns
            | TriggerType::SensitiveFileAccess
            | TriggerType::Lolbas => PostureKind::Alerted,

            TriggerType::ExploitAttempt
            | TriggerType::AdjacentCompromise
            | TriggerType::HeavyReconnaissance
            | TriggerType::CriticalFileModification => PostureKind::Engaged,

            TriggerType::ConfirmedIntrusion
            | TriggerType::PersistenceMechanism
            | TriggerType::LateralMovement
            | TriggerType::ExfiltrationPattern => PostureKind::Combat,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            TriggerType::Reconnaissance => "Reconnaissance",
            TriggerType::SuspiciousDns => "SuspiciousDns",
            TriggerType::SensitiveFileAccess => "SensitiveFileAccess",
            TriggerType::Lolbas => "Lolbas",
            TriggerType::ExploitAttempt => "ExploitAttempt",
            TriggerType::AdjacentCompromise => "AdjacentCompromise",
            TriggerType::HeavyReconnaissance => "HeavyReconnaissance",
            TriggerType::CriticalFileModification => "CriticalFileModification",
            TriggerType::ConfirmedIntrusion => "ConfirmedIntrusion",
            TriggerType::PersistenceMechanism => "PersistenceMechanism",
            TriggerType::LateralMovement => "LateralMovement",
            TriggerType::ExfiltrationPattern => "ExfiltrationPattern",
        }
    }
}

impl core::fmt::Display for TriggerType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One audit record per posture state change.
///
/// `trigger` is `None` for decay transitions (timer-driven down-shift).
/// `unix_ts_secs` is a wall-clock timestamp, captured at the moment of
/// the transition (not used by the state machine itself; the runtime
/// uses monotonic `Instant`s, immune to NTP jumps).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostureTransition {
    pub from: PostureKind,
    pub to: PostureKind,
    pub trigger: Option<TriggerType>,
    pub unix_ts_secs: u64,
    pub reason: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn posture_kind_orders_by_gravity() {
        assert!(PostureKind::Observing < PostureKind::Alerted);
        assert!(PostureKind::Alerted < PostureKind::Engaged);
        assert!(PostureKind::Engaged < PostureKind::Combat);
    }

    #[test]
    fn trigger_target_levels_are_consistent() {
        assert_eq!(
            TriggerType::Reconnaissance.target_level(),
            PostureKind::Alerted
        );
        assert_eq!(
            TriggerType::ExploitAttempt.target_level(),
            PostureKind::Engaged
        );
        assert_eq!(
            TriggerType::ConfirmedIntrusion.target_level(),
            PostureKind::Combat
        );
    }

    #[test]
    fn posture_transition_round_trips_through_serde_json() {
        let t = PostureTransition {
            from: PostureKind::Observing,
            to: PostureKind::Alerted,
            trigger: Some(TriggerType::Reconnaissance),
            unix_ts_secs: 1_700_000_000,
            reason: "demo".to_string(),
        };
        let json = serde_json::to_string(&t).expect("serialize");
        let parsed: PostureTransition = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.from, PostureKind::Observing);
        assert_eq!(parsed.to, PostureKind::Alerted);
        assert_eq!(parsed.trigger, Some(TriggerType::Reconnaissance));
    }

    #[test]
    fn decay_transition_serializes_without_trigger() {
        let t = PostureTransition {
            from: PostureKind::Alerted,
            to: PostureKind::Observing,
            trigger: None,
            unix_ts_secs: 1_700_000_000,
            reason: "decay 1h".to_string(),
        };
        let json = serde_json::to_string(&t).expect("serialize");
        assert!(json.contains("\"trigger\":null"));
    }
}
