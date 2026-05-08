//! R010 — Process executed from a web server document root.

use common::{Event, ResponseAction, Severity, Verdict};

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

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn { filename, .. } = event else {
            return None;
        };
        if !WEBROOTS.iter().any(|w| filename.starts_with(w)) {
            return None;
        }
        Some(build_verdict(
            self,
            event,
            ResponseAction::KillProcess,
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
            assert_eq!(v.action, ResponseAction::KillProcess);
            assert_eq!(v.severity, Severity::High);
        }
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
