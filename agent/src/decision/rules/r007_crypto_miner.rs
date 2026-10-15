//! R007 — Cryptocurrency miner, by name.
//!
//! External audit PROC-010: the rule killed the tree of any process whose
//! `comm` merely CONTAINED a miner's name — `xmrig-cleanup`, a monitoring
//! check named after what it looks for — and an operator had no allowlist
//! to stop it. Now:
//!
//! - an exact miner name, in `comm` or in the basename of the file the
//!   kernel executed (a symlink named `sysupd` to `xmrig` included), kills
//!   the tree, as before;
//! - a name that only contains one is recorded (Log, High);
//! - the process allowlist applies, judged on what the kernel executed.
//!
//! A name is chosen by whoever runs the binary: a miner renamed to
//! anything else evades this rule, and one renamed `xmrig-something` is
//! now only recorded. The behaviour of a miner (CPU, pool connections) is
//! the network rules' and the posture's.
//!
//! The rule is registered twice (external audit PROC-009): the exact-name
//! pass ([`R007CryptoMiner::new`]) near the head, ahead of the staging
//! rules it outranks, and the name-fragment pass
//! ([`R007CryptoMiner::name_fragments`]) after every process rule that
//! kills, so its record never stands in for a kill (`/tmp/xmrig-x` is
//! still killed by R001).

use std::sync::Arc;

use common::{Event, ResponseAction, Severity, Verdict};

use crate::config::comm_allowlist::{CommAllowlist, Judgement};
use crate::decision::{rules::build_verdict, Rule};

/// Miner program names, lower case. All fit in `TASK_COMM_LEN`.
const MINER_NAMES: &[&str] = &[
    "xmrig",
    "cpuminer",
    "minerd",
    "ccminer",
    "ethminer",
    "phoenixminer",
];

pub struct R007CryptoMiner {
    allowlist: Arc<CommAllowlist>,
    /// The name-fragment pass (records), not the exact-name pass (kills).
    fragments: bool,
}

impl R007CryptoMiner {
    /// The exact-name pass: kills the tree.
    pub fn new(allowlist: Arc<CommAllowlist>) -> Self {
        Self {
            allowlist,
            fragments: false,
        }
    }

    /// The name-fragment pass: a name that contains a miner's without
    /// being one is recorded. Silent on an exact name (the other pass's).
    pub fn name_fragments(allowlist: Arc<CommAllowlist>) -> Self {
        Self {
            allowlist,
            fragments: true,
        }
    }
}

impl Rule for R007CryptoMiner {
    fn id(&self) -> &'static str {
        "R007_CryptoMiner"
    }
    fn name(&self) -> &'static str {
        "Crypto miner"
    }
    fn category(&self) -> &'static str {
        "resource_abuse"
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn {
            comm,
            filename,
            exe,
            ..
        } = event
        else {
            return None;
        };
        let comm_lc = comm.to_ascii_lowercase();
        let image = exe.path_or(filename);
        let base_lc = image
            .rsplit('/')
            .next()
            .unwrap_or(image)
            .to_ascii_lowercase();
        let names = [comm_lc.as_str(), base_lc.as_str()];
        let exact = MINER_NAMES.iter().find(|n| names.contains(n));
        let found = match (self.fragments, exact) {
            (false, Some(n)) => *n,
            (false, None) | (true, Some(_)) => return None,
            (true, None) => *MINER_NAMES
                .iter()
                .find(|n| names.iter().any(|name| name.contains(**n)))?,
        };
        let judgement = super::judge_spawn(&self.allowlist, event);
        if judgement == Judgement::Allowed {
            return None;
        }
        let verdict = if self.fragments {
            build_verdict(
                self,
                event,
                ResponseAction::Log,
                Severity::High,
                &format!(
                    "Process name contains a cryptocurrency miner's ('{found}' in '{comm}', \
                     executable '{image}') without being it — recorded, not killed: a cleanup \
                     or monitoring tool can carry the name"
                ),
            )
        } else {
            build_verdict(
                self,
                event,
                ResponseAction::KillProcessTree,
                Severity::Critical,
                &format!("Cryptocurrency miner detected ('{found}')"),
            )
        };
        Some(judgement.apply(verdict, comm))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rules::testutil::{spawn, spawn_exe};

    fn exact() -> R007CryptoMiner {
        R007CryptoMiner::new(Arc::new(CommAllowlist::default()))
    }

    fn fragments() -> R007CryptoMiner {
        R007CryptoMiner::name_fragments(Arc::new(CommAllowlist::default()))
    }

    #[test]
    fn fires_on_known_miner_comms() {
        for n in MINER_NAMES {
            let v = exact()
                .evaluate(&spawn(n, "/tmp/whatever"))
                .unwrap_or_else(|| panic!("{n}"));
            assert_eq!(v.action, ResponseAction::KillProcessTree);
            // The fragment pass leaves an exact name to the exact pass.
            assert!(fragments().evaluate(&spawn(n, "/tmp/whatever")).is_none());
        }
    }

    #[test]
    fn ignores_unrelated_comms() {
        for rule in [exact(), fragments()] {
            assert!(rule.evaluate(&spawn("ls", "/usr/bin/ls")).is_none());
        }
    }

    #[test]
    fn match_is_case_insensitive() {
        let v = exact().evaluate(&spawn("XMRig", "/opt/XMRig")).unwrap();
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        assert_eq!(v.severity, Severity::Critical);
    }

    /// External audit PROC-010: a name that only contains a miner's is
    /// recorded, not killed — and the exact pass is silent on it.
    #[test]
    fn r007_substring_only_is_recorded() {
        for (comm, path) in [
            ("xmrig-cleanup", "/usr/local/bin/xmrig-cleanup"),
            ("check_minerd", "/usr/lib/nagios/plugins/check_minerd"),
            ("kthreadd_xmrig", "/opt/x/kthreadd_xmrig"),
        ] {
            assert!(exact().evaluate(&spawn(comm, path)).is_none(), "{comm}");
            let v = fragments().evaluate(&spawn(comm, path)).expect(comm);
            assert_eq!(v.action, ResponseAction::Log, "{comm}");
            assert_eq!(v.severity, Severity::High, "{comm}");
            assert!(
                v.reasoning.contains("recorded, not killed"),
                "{}",
                v.reasoning
            );
        }
    }

    /// External audit PROC-010: the executed file's basename counts — a
    /// symlink named `sysupd` to the miner, which sets `comm` to `sysupd`.
    #[test]
    fn r007_exact_name_of_the_executed_file_kills() {
        let e = spawn_exe("sysupd", "/usr/local/bin/sysupd", "/opt/pool/xmrig", 0);
        let v = exact().evaluate(&e).expect("the kernel ran xmrig");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        assert!(fragments().evaluate(&e).is_none());
    }

    /// External audit PROC-010: an operator allowlist, judged on what the
    /// kernel executed; a copy outside a system tree is not exempt.
    #[test]
    fn r007_allowlisted_by_identity_is_exempt() {
        let al = Arc::new(CommAllowlist::from_iter_owned(
            ["xmrig-cleanup".to_string()],
        ));
        let r = R007CryptoMiner::name_fragments(al);
        let installed = spawn_exe(
            "xmrig-cleanup",
            "xmrig-cleanup",
            "/usr/local/bin/xmrig-cleanup",
            0,
        );
        assert!(r.evaluate(&installed).is_none());
        let copy = spawn_exe("xmrig-cleanup", "./xmrig-cleanup", "/tmp/xmrig-cleanup", 0);
        let v = r.evaluate(&copy).expect("a copy in /tmp is not exempt");
        assert!(
            v.reasoning.contains("named 'xmrig-cleanup'"),
            "{}",
            v.reasoning
        );
    }
}
