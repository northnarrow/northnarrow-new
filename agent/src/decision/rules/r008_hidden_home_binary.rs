//! R008 — Executable in a hidden user directory.
//!
//! Many attackers drop persistence binaries in `~/.cache/`, `~/.foo/`,
//! etc. This rule alerts (does not kill) on any `/home/<user>/.<dot>`
//! exec that isn't covered by a hardcoded whitelist of legit
//! tooling-managed dotpaths.

use common::{Event, ResponseAction, Severity, Verdict};

use crate::decision::{rules::build_verdict, Rule};

/// Dot-prefixed user directories whose binaries are legitimately
/// executed (language toolchains, package managers, IDE caches, ...).
/// Match is "filename contains `/home/<user>/<entry>`": entries should
/// include a trailing slash to anchor the directory boundary.
const HOME_DOTPATH_WHITELIST: &[&str] = &[
    ".cargo/bin/",
    ".local/bin/",
    ".npm/",
    ".yarn/",
    ".rustup/",
    ".rbenv/",
    ".pyenv/",
    ".cache/",
    ".config/",
    ".nvm/",
    ".gem/",
];

pub struct R008HiddenHomeBinary;

impl R008HiddenHomeBinary {
    /// Extract the user-relative part after `/home/<user>/`. Returns
    /// `None` if the path isn't a `/home/<user>/...` path.
    fn user_relative(filename: &str) -> Option<&str> {
        let after_home = filename.strip_prefix("/home/")?;
        let slash = after_home.find('/')?;
        Some(&after_home[slash + 1..])
    }
}

impl Rule for R008HiddenHomeBinary {
    fn id(&self) -> &'static str {
        "R008_HiddenHomeBinary"
    }
    fn name(&self) -> &'static str {
        "Executable in hidden user directory"
    }
    fn category(&self) -> &'static str {
        "persistence"
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn { filename, .. } = event else {
            return None;
        };
        let rel = Self::user_relative(filename)?;
        if !rel.starts_with('.') {
            return None;
        }
        if HOME_DOTPATH_WHITELIST.iter().any(|w| rel.starts_with(w)) {
            return None;
        }
        Some(build_verdict(
            self,
            event,
            ResponseAction::Log,
            Severity::Medium,
            "Executable in hidden user directory — potential persistence",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::rules::testutil::spawn;

    #[test]
    fn fires_on_unknown_dot_directory() {
        let v = R008HiddenHomeBinary
            .evaluate(&spawn("backdoor", "/home/alice/.evil/backdoor"))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::Log);
        assert_eq!(v.severity, Severity::Medium);
    }

    #[test]
    fn ignores_whitelisted_paths() {
        for ok in [
            "/home/alice/.cargo/bin/cargo",
            "/home/alice/.local/bin/black",
            "/home/alice/.rustup/toolchains/stable/bin/rustc",
            "/home/alice/.cache/yay/build.sh",
        ] {
            assert!(
                R008HiddenHomeBinary.evaluate(&spawn("x", ok)).is_none(),
                "should NOT fire on {ok}"
            );
        }
    }

    #[test]
    fn ignores_non_home_and_non_dot_paths() {
        assert!(R008HiddenHomeBinary
            .evaluate(&spawn("ls", "/usr/bin/ls"))
            .is_none());
        // Visible (non-dot) home subdir.
        assert!(R008HiddenHomeBinary
            .evaluate(&spawn("hello", "/home/alice/projects/hello"))
            .is_none());
        // /root/.foo/ is not /home/<user>/ — out of scope (R009 covers
        // privileged-from-user-path; root exec from /root is normal).
        assert!(R008HiddenHomeBinary
            .evaluate(&spawn("x", "/root/.evil/x"))
            .is_none());
    }
}
