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
//! "Service-class uid" is [`super::is_service_uid`], shared with R016:
//! the system accounts below `UID_MIN` (1..999), `nobody` (65534) and
//! systemd's `DynamicUser=` range (61184..65519) — external audit
//! PROC-012, the class used to stop at 1000. Root (0), human users
//! (1000..60000) and container sub-uid ranges are deliberately excluded:
//! encoder use by those is too common to flag at this severity.
//! argv-aware refinement (what is being encoded) is deferred to T10.6.
//! The argv flags only enrich the reasoning; external audit EBPF-021: when
//! the kernel cut the argv, the reasoning says so.

use std::sync::Arc;

use nn_model::{Event, ResponseAction, Severity, Verdict};

use crate::config::comm_allowlist::CommAllowlist;
use crate::config::comm_allowlist::Judgement;
use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::{rules::build_verdict, Rule};
use crate::posture::host::PostureHost;

/// Encoding / encryption tool comms (design §7.1).
const ENCODING_TOOLS: &[&str] = &["base64", "xxd", "openssl"];

pub struct R015EncodingToolingServiceUid<H: PostureHost> {
    allowlist: Arc<CommAllowlist<H>>,
}

impl<H: PostureHost> R015EncodingToolingServiceUid<H> {
    pub fn new(allowlist: Arc<CommAllowlist<H>>) -> Self {
        Self { allowlist }
    }
}

impl<H: PostureHost> Rule for R015EncodingToolingServiceUid<H> {
    fn id(&self) -> &'static str {
        "R015_EncodingToolingServiceUid"
    }
    fn name(&self) -> &'static str {
        "Encoding tooling exec by service account"
    }
    fn category(&self) -> &'static str {
        "defense_evasion"
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[
            AttackRef::new(Tactic::Stealth, "T1027"),
            AttackRef::new(Tactic::Stealth, "T1140"),
            AttackRef::new(Tactic::CommandAndControl, "T1132"),
        ];
        ATTACK
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn {
            comm, uid, argv, ..
        } = event
        else {
            return None;
        };
        if !ENCODING_TOOLS.contains(&comm.as_str()) {
            return None;
        }
        // Service-class uid only (PROC-012: nobody and DynamicUser too).
        if !super::is_service_uid(*uid) {
            return None;
        }
        // External audit NETR-003 class: the allowlist judged on what the
        // kernel executed, not on the comm the process chose.
        let judgement = super::judge_spawn(&self.allowlist, event);
        if judgement == Judgement::Allowed {
            return None;
        }
        // D5: a decode/decrypt flag in argv (`base64 -d`, `openssl enc
        // -d`) is the payload-decode tell. Additive — base fires anyway.
        let mut reasoning = String::from(
            "Encoding/encryption tool (base64/xxd/openssl) exec by a \
             service account — exfil-staging / payload-decode shape \
             (T1027/T1132); posture → ALERTED",
        );
        if argv
            .iter()
            .any(|a| a == "-d" || a == "--decode" || a == "enc" || a == "-aes-256-cbc")
        {
            reasoning = format!(
                "{reasoning} — decode/cipher flags in argv ({})",
                argv.join(" ")
            );
        }
        // External audit EBPF-021: a flag past a cut argv was not seen.
        let reasoning = super::with_argv_cut_note(reasoning, event);
        Some(judgement.apply(
            build_verdict(
                self,
                event,
                ResponseAction::Log,
                Severity::Medium,
                &reasoning,
            ),
            comm,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // R08b (lab PR 251): on the portable test host.
    use crate::posture::host::testing::TestHost as H;
    type CommAllowlist = crate::config::comm_allowlist::CommAllowlist<H>;
    type R015EncodingToolingServiceUid = super::R015EncodingToolingServiceUid<H>;
    use crate::decision::rules::testutil::{argv_cut, spawn_as, spawn_full};

    fn rule() -> R015EncodingToolingServiceUid {
        R015EncodingToolingServiceUid::new(Arc::new(CommAllowlist::default()))
    }

    #[test]
    fn argv_decode_flag_enriches_reasoning() {
        let ev = spawn_full(
            "base64",
            "/usr/bin/base64",
            33,
            &["base64", "-d", "payload.b64"],
            "sh",
        );
        let v = rule().evaluate(&ev).expect("fires");
        assert!(v.reasoning.contains("decode/cipher flags in argv"));
    }

    /// External audit EBPF-021: a decode flag past a cut argv was not seen;
    /// the reasoning says so, the verdict is the same.
    #[test]
    fn r015_cut_argv_is_named() {
        let ev = argv_cut(spawn_full(
            "base64",
            "/usr/bin/base64",
            33,
            &["base64", "-w", "0"],
            "sh",
        ));
        let v = rule().evaluate(&ev).expect("fires");
        assert_eq!(
            (v.action, v.severity),
            (ResponseAction::Log, Severity::Medium)
        );
        assert!(
            v.reasoning.contains("argv truncated at 511 bytes"),
            "{}",
            v.reasoning
        );
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

    /// External audit PROC-012: a `DynamicUser=yes` unit's transient uid.
    #[test]
    fn dynamic_user_uid_is_service_class() {
        let v = rule()
            .evaluate(&spawn_as(61_500, "base64", "/usr/bin/base64"))
            .expect("fires");
        assert_eq!(v.rule_id, "R015_EncodingToolingServiceUid");
        assert_eq!(v.action, ResponseAction::Log);
        assert_eq!(v.severity, Severity::Medium);
    }

    /// External audit PROC-012: `nobody` (65534).
    #[test]
    fn nobody_is_service_class() {
        let v = rule()
            .evaluate(&spawn_as(65_534, "openssl", "/usr/bin/openssl"))
            .expect("fires");
        assert_eq!(v.rule_id, "R015_EncodingToolingServiceUid");
        assert_eq!(v.action, ResponseAction::Log);
    }

    #[test]
    fn ignores_root_or_human_uid() {
        // Root encoder use is too common to flag here.
        assert!(rule()
            .evaluate(&spawn_as(0, "base64", "/usr/bin/base64"))
            .is_none());
        // Human user (uid >= 1000) likewise, and a rootless container's
        // sub-uid (PROC-012: the range's owner's standing).
        for uid in [1000, 60_000, 100_000, 100_032] {
            assert!(
                rule()
                    .evaluate(&spawn_as(uid, "openssl", "/usr/bin/openssl"))
                    .is_none(),
                "{uid}"
            );
        }
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
