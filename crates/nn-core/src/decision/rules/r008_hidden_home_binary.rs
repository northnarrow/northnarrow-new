//! R008 — Executable in a hidden user directory.
//!
//! Many attackers drop persistence binaries in `~/.cache/`, `~/.foo/`,
//! etc. This rule alerts (does not kill) on any `/home/<user>/.<dot>`
//! exec that isn't covered by a hardcoded whitelist of legit
//! tooling-managed dotpaths.
//!
//! The path judged is the file the kernel executed (review 61): a script
//! is judged by its interpreter, so only native executables matter here
//! (the caller's path stands in only where the kernel's is unknown, as in
//! the tracepoint mode).

use nn_model::{Event, ResponseAction, Severity, Verdict};

use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::{rules::build_verdict, Rule};

/// Dot-prefixed user directories whose binaries are legitimately
/// executed (language toolchains, package managers, the tools that
/// download their own executables).
///
/// An entry matches as a prefix of the path relative to `/home/<user>/`
/// (`/home/alice/.cargo/bin/x` → `.cargo/bin/x` starts with `.cargo/bin/`),
/// so each entry ends with a slash to anchor the directory boundary.
///
/// External audit PROC-013: `.cache/` and `.config/` were entries of their
/// own, so a binary dropped in any directory under them — `~/.cache/x/`,
/// or the user's persistence directories `~/.config/systemd/` (user units)
/// and `~/.config/autostart/` (`.desktop` files), where nothing is meant
/// to execute — drew no record. Under those two only the directories of
/// named tools that run their own executables there are exempt:
///
/// - `.cache/go-build/`: Go 1.24 and later run the executables of
///   `go run` and `go tool` from the build cache;
/// - `.cache/bazel/`: Bazel's output base (`_bazel_<user>`), its tools and
///   test binaries; `.cache/bazelisk/`: the Bazel releases Bazelisk fetches;
/// - `.cache/ms-playwright/`, `.cache/puppeteer/`, `.cache/Cypress/`,
///   `.cache/selenium/`: the browsers and drivers of the browser-testing
///   tools (Selenium Manager's included);
/// - `.cache/pre-commit/`: pre-commit's hook environments (nodeenv's
///   `node`, Go and Rust hooks); `.cache/uv/`: uv's tool environments
///   (`uvx ruff`); `.cache/pypoetry/virtualenvs/`: Poetry's virtualenvs;
/// - `.cache/yay/`, `.cache/paru/`: the AUR helpers' builds (`makepkg`'s
///   `check()` runs what it compiled);
/// - `.cache/coursier/arc/`: the JDKs Coursier unpacks (Metals, `cs java`);
/// - `.cache/JetBrains/RemoteDev/`: the IDE backends of JetBrains Gateway;
/// - `.config/{Code,Code - OSS,VSCodium,Cursor}/User/globalStorage/`: the
///   language servers VS Code-family extensions download (clangd, zls);
///   `.config/coc/extensions/`: coc.nvim's, likewise.
const HOME_DOTPATH_WHITELIST: &[&str] = &[
    ".cargo/bin/",
    ".local/bin/",
    ".npm/",
    ".yarn/",
    ".rustup/",
    ".rbenv/",
    ".pyenv/",
    ".nvm/",
    ".gem/",
    ".cache/go-build/",
    ".cache/bazel/",
    ".cache/bazelisk/",
    ".cache/ms-playwright/",
    ".cache/puppeteer/",
    ".cache/Cypress/",
    ".cache/selenium/",
    ".cache/pre-commit/",
    ".cache/uv/",
    ".cache/pypoetry/virtualenvs/",
    ".cache/yay/",
    ".cache/paru/",
    ".cache/coursier/arc/",
    ".cache/JetBrains/RemoteDev/",
    ".config/Code/User/globalStorage/",
    ".config/Code - OSS/User/globalStorage/",
    ".config/VSCodium/User/globalStorage/",
    ".config/Cursor/User/globalStorage/",
    ".config/coc/extensions/",
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
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::Stealth, "T1564.001")];
        ATTACK
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn { filename, exe, .. } = event else {
            return None;
        };
        // Review 61: the file the kernel executed, not the caller's string.
        let filename = exe.path_or(filename);
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
            "/home/alice/.cache/go-build/3f/3f9a-d/hello",
            "/home/alice/.cache/bazel/_bazel_alice/install/abc/embedded_tools/x",
            "/home/alice/.cache/ms-playwright/chromium-1140/chrome-linux/chrome",
            "/home/alice/.cache/pre-commit/repoabc/node_env-default/bin/node",
            "/home/alice/.cache/uv/archive-v0/abc/bin/ruff",
            "/home/alice/.cache/JetBrains/RemoteDev/dist/abc/jbr/bin/java",
            "/home/alice/.config/Code/User/globalStorage/llvm-vs-code-extensions.vscode-clangd/install/18/clangd_18/bin/clangd",
        ] {
            assert!(
                R008HiddenHomeBinary.evaluate(&spawn("x", ok)).is_none(),
                "should NOT fire on {ok}"
            );
        }
    }

    /// External audit PROC-013: a binary anywhere else under `~/.cache/`
    /// or `~/.config/` is recorded.
    #[test]
    fn cache_and_config_are_not_exempt_as_a_whole() {
        for bad in [
            "/home/alice/.cache/x/payload",
            "/home/alice/.cache/payload",
            "/home/alice/.cache/go-buildx/payload",
            "/home/alice/.config/x/payload",
            "/home/alice/.config/Code/payload",
        ] {
            let v = R008HiddenHomeBinary
                .evaluate(&spawn("payload", bad))
                .unwrap_or_else(|| panic!("should fire on {bad}"));
            assert_eq!(v.action, ResponseAction::Log, "{bad}");
            assert_eq!(v.severity, Severity::Medium, "{bad}");
        }
    }

    /// External audit PROC-013: user units hold unit files; nothing is
    /// meant to execute from there.
    #[test]
    fn user_unit_dir_is_never_exempt() {
        for bad in [
            "/home/alice/.config/systemd/user/updater",
            "/home/alice/.config/systemd/user/default.target.wants/x",
        ] {
            assert!(
                R008HiddenHomeBinary.evaluate(&spawn("x", bad)).is_some(),
                "{bad}"
            );
        }
    }

    /// External audit PROC-013: autostart holds `.desktop` files.
    #[test]
    fn autostart_dir_is_never_exempt() {
        assert!(R008HiddenHomeBinary
            .evaluate(&spawn("x", "/home/alice/.config/autostart/x"))
            .is_some());
    }

    /// The rule judges the file the kernel executed: a caller's string
    /// under an exempt directory does not exempt an image elsewhere.
    #[test]
    fn the_executed_image_is_judged() {
        let ev = crate::decision::rules::testutil::spawn_exe(
            "x",
            "/home/alice/.cache/uv/x",
            "/home/alice/.cache/x/x",
            0,
        );
        assert!(R008HiddenHomeBinary.evaluate(&ev).is_some());
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
