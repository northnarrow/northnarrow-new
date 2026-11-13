//! Lot 341 (alpha 2/4): the agent's response profile, and the ONE
//! resolver of the agent-wide no-enforcement gate.
//!
//! Two profiles:
//!
//! - **`alpha`** — observe-only. Detection, posture and the evidence chains
//!   run as always; no response action touches a user program (no kill, no
//!   isolation, no quarantine, no exec-queue hold, no enforce deny): every
//!   verdict is recorded with what it *would have* done. The agent's own
//!   self-protection (the anti-tamper deny hooks on its files, processes,
//!   maps and cgroup) is not a response and stays on.
//! - **`enforcing`** — the responses run.
//!
//! Where the profile comes from, strongest first ([`resolve`]):
//!
//! 1. a signed `profile.local` overlay (`nn-admin config overlay set
//!    profile`, a key with `config-manage`, for this agent's id) — the only
//!    way to switch an installed agent between the two, at its next start;
//! 2. the install manifest's `profile`, which `install.sh` writes: `alpha`
//!    on a fresh install unless `--profile enforcing` was asked for; kept by
//!    every upgrade;
//! 3. neither: `enforcing`, the behaviour of every agent before this lot
//!    (an install older than the field, a developer run, the tests).
//!
//! The no-enforcement gate is then `--detect-only` OR a detect-only
//! variable OR the `alpha` profile ([`detect_only_gate`]); the start reads
//! it once and hands the one value to every response path and deny switch.

use std::fmt;

/// Where the signed overlay lives on an install (`--profile-local`).
pub const DEFAULT_LOCAL: &str = "/etc/northnarrow/profile.local";

/// The keyword of the profile's line in `profile.local` and of the install
/// manifest's field.
pub const PROFILE_KEY: &str = "profile";

/// The two profiles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Profile {
    /// Observe-only: every verdict recorded as "would have", no response.
    Alpha,
    /// The responses run.
    Enforcing,
}

impl Profile {
    /// Both, in the order the docs name them.
    pub const ALL: [Profile; 2] = [Profile::Alpha, Profile::Enforcing];

    /// The profile's name (`alpha`, `enforcing`).
    pub fn as_str(self) -> &'static str {
        match self {
            Profile::Alpha => "alpha",
            Profile::Enforcing => "enforcing",
        }
    }

    /// The profile a name gives (exact, lower case).
    pub fn from_name(name: &str) -> Option<Profile> {
        Profile::ALL.into_iter().find(|p| p.as_str() == name)
    }

    /// No response action runs under this profile.
    pub fn observe_only(self) -> bool {
        matches!(self, Profile::Alpha)
    }

    /// The content of a `profile.local` (or of the install manifest's
    /// field, a bare name): blank lines and `#` comments, and exactly one
    /// `profile = <alpha|enforcing>` line. Anything else is refused whole —
    /// a signature must never cover a file the agent reads differently.
    pub fn parse(text: &str) -> Result<Profile, String> {
        let mut found = None;
        for (i, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let lineno = i + 1;
            let Some((key, value)) = line.split_once('=') else {
                return Err(format!(
                    "line {lineno}: expected `{PROFILE_KEY} = alpha|enforcing`"
                ));
            };
            if key.trim() != PROFILE_KEY {
                return Err(format!(
                    "line {lineno}: unknown key `{}` (only `{PROFILE_KEY}`)",
                    key.trim()
                ));
            }
            let value = value.trim();
            let Some(p) = Profile::from_name(value) else {
                return Err(format!(
                    "line {lineno}: unknown profile `{value}` (alpha or enforcing)"
                ));
            };
            if found.replace(p).is_some() {
                return Err(format!("line {lineno}: a second `{PROFILE_KEY}` line"));
            }
        }
        found.ok_or_else(|| format!("no `{PROFILE_KEY} = alpha|enforcing` line"))
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where the profile in force came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfileSource {
    /// The signed `profile.local` overlay.
    Overlay,
    /// The install manifest's field.
    InstallManifest,
    /// Neither: the built-in default.
    Default,
}

impl ProfileSource {
    /// A short label for the boot line, the status and `agent_boot`.
    pub fn label(&self) -> &'static str {
        match self {
            ProfileSource::Overlay => "signed profile.local",
            ProfileSource::InstallManifest => "install manifest",
            ProfileSource::Default => "built-in default",
        }
    }
}

/// The profile in force and where it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedProfile {
    pub profile: Profile,
    pub source: ProfileSource,
}

impl ResolvedProfile {
    /// `alpha (install manifest)`.
    pub fn describe(&self) -> String {
        format!("{} ({})", self.profile, self.source.label())
    }
}

/// The built-in default: an agent with no profile from its install is the
/// agent it was before this lot.
pub const DEFAULT_PROFILE: Profile = Profile::Enforcing;

/// The profile in force: the signed overlay's (`overlay`, only when the
/// overlay gate verified it), else the install manifest's (`manifest`, only
/// when the manifest describes this binary), else [`DEFAULT_PROFILE`].
pub fn resolve(overlay: Option<Profile>, manifest: Option<Profile>) -> ResolvedProfile {
    match (overlay, manifest) {
        (Some(profile), _) => ResolvedProfile {
            profile,
            source: ProfileSource::Overlay,
        },
        (None, Some(profile)) => ResolvedProfile {
            profile,
            source: ProfileSource::InstallManifest,
        },
        (None, None) => ResolvedProfile {
            profile: DEFAULT_PROFILE,
            source: ProfileSource::Default,
        },
    }
}

/// The agent-wide no-enforcement gate, resolved once at the start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetectOnly {
    /// No response action and no enforce deny of a user program.
    pub on: bool,
    /// What switched it on (MAIN-008: the signed `agent_boot` names it):
    /// `--detect-only`, `NN_DETECT_ONLY=1`, `profile alpha (…)`.
    pub source: Option<String>,
}

/// The gate from its inputs: the command line's `--detect-only`
/// (`cli_flag`), the detect-only variable set in the environment
/// (`env`, [`super::config::detect_only_env`]) and the profile in force.
/// The first one set names the source.
pub fn detect_only_gate(
    cli_flag: bool,
    env: Option<(&str, String)>,
    profile: &ResolvedProfile,
) -> DetectOnly {
    let source = if cli_flag {
        Some("--detect-only".to_string())
    } else if let Some((name, value)) = env {
        Some(format!("{name}={value}"))
    } else if profile.profile.observe_only() {
        Some(format!("profile {}", profile.describe()))
    } else {
        None
    };
    DetectOnly {
        on: source.is_some(),
        source,
    }
}

/// The text a record carries for a response the gate suppressed:
/// `would have: KillProcess`. The action name follows the prefix, so a
/// reader keyed on it finds both what ran (`KillProcess…`, first word) and
/// what would have (`would have: KillProcess`).
pub fn would_have(action: &str) -> String {
    format!("{WOULD_HAVE_PREFIX}{action}")
}

/// The prefix of [`would_have`].
pub const WOULD_HAVE_PREFIX: &str = "would have: ";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_profile_file_names_exactly_one_profile() {
        assert_eq!(Profile::parse("profile = alpha\n"), Ok(Profile::Alpha));
        assert_eq!(
            Profile::parse("# switched by the operator\n\nprofile=enforcing\n"),
            Ok(Profile::Enforcing)
        );
        for bad in [
            "",
            "# nothing\n",
            "alpha\n",
            "profile = Alpha\n",
            "profile = observe\n",
            "mode = alpha\n",
            "profile = alpha\nprofile = alpha\n",
            "profile = alpha\nextra\n",
        ] {
            assert!(Profile::parse(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn the_signed_overlay_wins_then_the_install_then_enforcing() {
        let r = resolve(Some(Profile::Enforcing), Some(Profile::Alpha));
        assert_eq!(r.profile, Profile::Enforcing);
        assert_eq!(r.source, ProfileSource::Overlay);
        let r = resolve(Some(Profile::Alpha), Some(Profile::Enforcing));
        assert_eq!(r.profile, Profile::Alpha);
        assert_eq!(r.source, ProfileSource::Overlay);
        let r = resolve(None, Some(Profile::Alpha));
        assert_eq!(r.profile, Profile::Alpha);
        assert_eq!(r.source, ProfileSource::InstallManifest);
        let r = resolve(None, None);
        assert_eq!(r.profile, Profile::Enforcing);
        assert_eq!(r.source, ProfileSource::Default);
    }

    /// Named (lot 341): the alpha profile switches the one gate on, and
    /// says so; enforcing leaves it to the flag and the variable.
    #[test]
    fn the_alpha_profile_turns_the_no_enforcement_gate_on() {
        let alpha = resolve(None, Some(Profile::Alpha));
        let g = detect_only_gate(false, None, &alpha);
        assert!(g.on);
        assert_eq!(
            g.source.as_deref(),
            Some("profile alpha (install manifest)")
        );
        let enforcing = resolve(None, None);
        let g = detect_only_gate(false, None, &enforcing);
        assert!(!g.on);
        assert_eq!(g.source, None);
        // the flag and the variable keep their meaning, and name themselves
        let g = detect_only_gate(true, None, &enforcing);
        assert!(g.on);
        assert_eq!(g.source.as_deref(), Some("--detect-only"));
        let g = detect_only_gate(false, Some(("NN_DETECT_ONLY", "yes".into())), &enforcing);
        assert!(g.on);
        assert_eq!(g.source.as_deref(), Some("NN_DETECT_ONLY=yes"));
        // a signed enforcing never switches off a flag or a variable
        let signed = resolve(Some(Profile::Enforcing), Some(Profile::Alpha));
        assert!(detect_only_gate(true, None, &signed).on);
    }

    #[test]
    fn a_suppressed_response_reads_would_have() {
        assert_eq!(would_have("KillProcess"), "would have: KillProcess");
        assert!(would_have("Quarantine").starts_with(WOULD_HAVE_PREFIX));
    }
}
