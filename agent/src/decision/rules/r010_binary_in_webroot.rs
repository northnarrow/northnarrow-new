//! R010 — Process executed from a web server document root.
//!
//! Lab PR 166: the executable is the payload itself, so the response is
//! the tree, as for R001.

use nn_model::{Event, ResponseAction, Severity, Verdict};

use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::{rules::build_verdict, Rule};

const WEBROOTS: &[&str] = &[
    "/var/www/",
    "/srv/www/",
    "/usr/share/nginx/html/",
    "/var/lib/nginx/",
    "/var/lib/apache2/",
];

pub struct R010BinaryInWebroot;

impl Rule for R010BinaryInWebroot {
    fn id(&self) -> &'static str {
        "R010_BinaryInWebroot"
    }
    fn name(&self) -> &'static str {
        "Exec from web document root"
    }
    fn category(&self) -> &'static str {
        "execution"
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::Persistence, "T1505.003")];
        ATTACK
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn { filename, exe, .. } = event else {
            return None;
        };
        // Review 61: the file the kernel executed, not the caller's string.
        let filename = exe.path_or(filename);
        if !WEBROOTS.iter().any(|w| filename.starts_with(w)) {
            return None;
        }
        Some(build_verdict(
            self,
            event,
            ResponseAction::KillProcessTree,
            Severity::High,
            "Process executed from web server document root — webshell indicator",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rules::testutil::spawn;

    #[test]
    fn fires_on_each_webroot() {
        for prefix in WEBROOTS {
            let path = format!("{prefix}payload");
            let v = R010BinaryInWebroot
                .evaluate(&spawn("payload", &path))
                .unwrap_or_else(|| panic!("should fire on {path}"));
            assert_eq!(v.action, ResponseAction::KillProcessTree);
            assert_eq!(v.severity, Severity::High);
        }
    }

    /// Lab PR 166: a webshell's forked children die with it.
    #[test]
    fn r010_kills_the_process_tree() {
        let v = R010BinaryInWebroot
            .evaluate(&spawn("payload", "/var/www/html/payload"))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
    }

    #[test]
    fn ignores_non_webroot_paths() {
        assert!(R010BinaryInWebroot
            .evaluate(&spawn("ls", "/usr/bin/ls"))
            .is_none());
        assert!(R010BinaryInWebroot
            .evaluate(&spawn("php", "/usr/bin/php"))
            .is_none());
    }

    #[test]
    fn does_not_match_lookalike_prefixes() {
        // "/var/wwwfoo/..." should not match.
        assert!(R010BinaryInWebroot
            .evaluate(&spawn("x", "/var/wwwfoo/x"))
            .is_none());
        // The directory itself without a binary is not an exec target,
        // but we still don't want a "false-prefix" match.
        assert!(R010BinaryInWebroot
            .evaluate(&spawn("x", "/var/www"))
            .is_none());
    }
}
