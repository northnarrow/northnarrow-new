//! R005 — Netcat-family tool launched. Alert only; netcat has legit uses.

use nn_model::{Event, ResponseAction, Severity, Verdict};

use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::{rules::build_verdict, Rule};
use crate::posture::host::PostureHost;
use crate::posture::lineage::AuthSessionTracker;

const NETCAT_COMMS: &[&str] = &["nc", "ncat", "netcat", "nc.openbsd", "nc.traditional"];

/// Lot 350: an exec whose argv names a path in cloud-init's socket
/// directory (for the journal line only).
fn names_cloud_init_socket(event: &Event) -> bool {
    matches!(event, Event::ProcessSpawn { argv, .. }
        if argv.iter().any(|a| a.starts_with(crate::posture::cloud_init::CLOUD_INIT_SOCKET_DIR)))
}

/// Lot 350 (F2-3): with the lineage, cloud-init's own netcat asking a boot
/// phase on its unix socket (`crate::posture::cloud_init`, by identity
/// only) is recorded at Low — every boot of a cloud image ran it as root,
/// High. Every other netcat is High, as before.
pub struct R005NetcatExec<H: PostureHost> {
    lineage: Option<AuthSessionTracker<H>>,
}

impl<H: PostureHost> Default for R005NetcatExec<H> {
    fn default() -> Self {
        Self { lineage: None }
    }
}

impl<H: PostureHost> R005NetcatExec<H> {
    /// Lot 350: the lineage cloud-init's own netcat is recognised on.
    pub fn with_lineage(mut self, lineage: Option<AuthSessionTracker<H>>) -> Self {
        self.lineage = lineage;
        self
    }
}

impl<H: PostureHost> Rule for R005NetcatExec<H> {
    fn id(&self) -> &'static str {
        "R005_NetcatExec"
    }
    fn name(&self) -> &'static str {
        "Netcat family launched"
    }
    fn category(&self) -> &'static str {
        "lateral_movement"
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::CommandAndControl, "T1095")];
        ATTACK
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn { comm, .. } = event else {
            return None;
        };
        if !NETCAT_COMMS.iter().any(|c| comm == c) {
            return None;
        }
        if let Some(lineage) = self.lineage.as_ref() {
            match crate::posture::cloud_init::cloud_init_check(lineage, event) {
                Ok(said) => {
                    return Some(build_verdict(
                        self,
                        event,
                        ResponseAction::Log,
                        Severity::Low,
                        &format!(
                            "Netcat launched by cloud-init on its own unix socket — recorded: {said}"
                        ),
                    ));
                }
                // lot 350: a netcat naming cloud-init's socket that is not
                // cloud-init's own: which part of the identity failed, in the
                // agent's journal (the record's text is unchanged)
                Err(why) if names_cloud_init_socket(event) => tracing::info!(
                    rule = "R005_NetcatExec",
                    "not cloud-init's own netcat on its unix socket: {why}"
                ),
                Err(_) => {}
            }
        }
        Some(build_verdict(
            self,
            event,
            ResponseAction::Log,
            Severity::High,
            "Netcat-family tool launched — possible reverse shell vector",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rules::testutil::spawn;
    use crate::posture::host::testing::TestHost;

    type R005 = R005NetcatExec<TestHost>;

    #[test]
    fn fires_on_each_netcat_alias() {
        for comm in NETCAT_COMMS {
            let v = R005::default()
                .evaluate(&spawn(comm, "/usr/bin/nc"))
                .unwrap_or_else(|| panic!("rule should fire on {comm}"));
            assert_eq!(v.action, ResponseAction::Log);
            assert_eq!(v.severity, Severity::High);
        }
    }

    #[test]
    fn ignores_unrelated_comms() {
        assert!(R005::default()
            .evaluate(&spawn("ls", "/usr/bin/ls"))
            .is_none());
    }

    #[test]
    fn does_not_match_substrings() {
        // "ncurses-tool" contains "nc" as a substring but is not nc.
        assert!(R005::default()
            .evaluate(&spawn("ncurses-tool", "/usr/bin/ncurses-tool"))
            .is_none());
    }

    /// Lot 350 (named, F2-3): with the lineage, cloud-init's own netcat
    /// (`crate::posture::cloud_init`) is recorded at Low; the same netcat
    /// with an inet argument, or any netcat the lineage does not vouch for,
    /// stays High.
    #[test]
    fn r005_records_cloud_init_s_own_netcat_at_low_only() {
        let (_tmp, t) = crate::posture::cloud_init::tests_support::cloud_final_host();
        let rule = R005NetcatExec::default().with_lineage(Some(t));
        let own = crate::posture::cloud_init::tests_support::netcat(&[
            "nc",
            "-U",
            "/run/cloud-init/share/final.sock",
        ]);
        let v = rule.evaluate(&own).expect("recorded");
        assert_eq!((v.action, v.severity), (ResponseAction::Log, Severity::Low));
        assert!(
            v.reasoning.contains("cloud-final.service"),
            "{}",
            v.reasoning
        );
        let inet =
            crate::posture::cloud_init::tests_support::netcat(&["nc", "203.0.113.7", "4444"]);
        let v = rule.evaluate(&inet).expect("recorded");
        assert_eq!(v.severity, Severity::High);
        // without the lineage, as on `main`
        let v = R005NetcatExec::<crate::posture::host::testing::IdTestHost>::default()
            .evaluate(&own)
            .expect("recorded");
        assert_eq!(v.severity, Severity::High);
    }
}
