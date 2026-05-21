//! R015 — Encoding/encryption tooling exec by a service-class uid
//! (Tappa 10.5 D2).
//!
//! MITRE T1027 (Obfuscated Files or Information) / T1132 (Data
//! Encoding). `base64` / `xxd` / `openssl` run by a *service account*
//! (not a human user, not root) is an exfil-staging / payload-decode
//! shape — daemons rarely shell out to encoders interactively. Scored
//! Medium with a Log action (FP-prone for humans, so scoped to
//! service uids), gated by `process-comm-allowlist`. Design §7.1.
//!
//! "Service-class uid" is approximated as a non-root system account:
//! `uid != 0 && uid < 1000`. The 1000 boundary is the long-standing
//! Linux `UID_MIN` convention (`/etc/login.defs`) separating system
//! daemons from human logins. Root (0) and human users (>= 1000) are
//! deliberately excluded — encoder use by those is too common to flag
//! at this severity. argv-aware refinement (what is being encoded) is
//! deferred to T10.6.

use std::sync::Arc;

use common::{Event, ResponseAction, Severity, Verdict};

use crate::config::comm_allowlist::CommAllowlist;
use crate::decision::{rules::build_verdict, Rule};

/// Encoding / encryption tool comms (design §7.1).
const ENCODING_TOOLS: &[&str] = &["base64", "xxd", "openssl"];

/// Linux `UID_MIN` boundary: accounts below this (and non-root) are
/// system/service accounts.
const SYSTEM_UID_CEILING: u32 = 1000;

pub struct R015EncodingToolingServiceUid {
    allowlist: Arc<CommAllowlist>,
}

impl R015EncodingToolingServiceUid {
    pub fn new(allowlist: Arc<CommAllowlist>) -> Self {
        Self { allowlist }
    }
}

impl Rule for R015EncodingToolingServiceUid {
    fn id(&self) -> &'static str {
        "R015_EncodingToolingServiceUid"
    }
    fn name(&self) -> &'static str {
        "Encoding tooling exec by service account"
    }
    fn category(&self) -> &'static str {
        "defense_evasion"
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn { comm, uid, .. } = event else {
            return None;
        };
        if !ENCODING_TOOLS.contains(&comm.as_str()) {
            return None;
        }
        // Service-class uid only: non-root system account.
        if *uid == 0 || *uid >= SYSTEM_UID_CEILING {
            return None;
        }
        if self.allowlist.contains(comm) {
            return None;
        }
        Some(build_verdict(
            self,
            event,
            ResponseAction::Log,
            Severity::Medium,
            "Encoding/encryption tool (base64/xxd/openssl) exec by a \
             service account — exfil-staging / payload-decode shape \
             (T1027/T1132); posture → ALERTED",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rules::testutil::spawn_as;

    fn rule() -> R015EncodingToolingServiceUid {
        R015EncodingToolingServiceUid::new(Arc::new(CommAllowlist::default()))
    }

    #[test]
    fn fires_on_encoder_by_service_uid() {
        // uid 33 = www-data on Debian — a service account.
        for tool in ENCODING_TOOLS {
            let v = rule()
                .evaluate(&spawn_as(33, tool, &format!("/usr/bin/{tool}")))
                .unwrap_or_else(|| panic!("should fire on {tool}"));
            assert_eq!(v.rule_id, "R015_EncodingToolingServiceUid");
            assert_eq!(v.action, ResponseAction::Log);
            assert_eq!(v.severity, Severity::Medium);
        }
    }

    #[test]
    fn ignores_root_or_human_uid() {
        // Root encoder use is too common to flag here.
        assert!(rule()
            .evaluate(&spawn_as(0, "base64", "/usr/bin/base64"))
            .is_none());
        // Human user (uid >= 1000) likewise.
        assert!(rule()
            .evaluate(&spawn_as(1000, "openssl", "/usr/bin/openssl"))
            .is_none());
        // Non-encoder by a service uid is not R015's concern.
        assert!(rule()
            .evaluate(&spawn_as(33, "ls", "/usr/bin/ls"))
            .is_none());
    }

    #[test]
    fn allowlisted_comm_is_exempt() {
        let r = R015EncodingToolingServiceUid::new(Arc::new(CommAllowlist::from_iter_owned([
            "openssl".to_string(),
        ])));
        assert!(r
            .evaluate(&spawn_as(33, "openssl", "/usr/bin/openssl"))
            .is_none());
        // A non-allowlisted encoder by a service uid still fires.
        assert!(r
            .evaluate(&spawn_as(33, "base64", "/usr/bin/base64"))
            .is_some());
    }
}
