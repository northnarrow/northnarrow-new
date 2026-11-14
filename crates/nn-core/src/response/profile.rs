//! Lot 341 (alpha 2/4): the agent's response profile, and the ONE
//! resolver of the agent-wide no-enforcement gate.
//!
//! Two profiles:
//!
//! - **`alpha`** — observe-only. Detection, posture and the evidence chains
//!   run as always; no response action touches a user program (no kill, no
//!   isolation, no quarantine, no exec-queue hold, no enforce deny): every
//!   verdict is recorded with what it *would have* done. The host's
//!   integrity and the agent's self-protection are not responses and stay
//!   enforced: the deny hooks on its files, processes, maps and cgroup, and
//!   (the review of #550) the host-wide denies that would blind, freeze or
//!   kill it — a foreign tracing BPF load, the kprobes and lockdown
//!   switches, the sysctl guard, a cgroup v1 write, a ptrace of PID 1, a
//!   kexec image, an untrusted module.
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
            // the review of #553 (F2): the chain's reader matches it
            ProfileSource::Overlay => nn_evidence::audit::PROFILE_SOURCE_SIGNED,
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

/// Lot 341 (the review of #550, F8): the alarm of an `alpha` start after a
/// run of the `enforcing` profile when nothing signed asked for it — the
/// profile is `alpha` and not from a verified `profile.local` (a deleted
/// overlay, a manifest edited while the agent was stopped). A signed
/// `profile = alpha` is the operator's switch: no alarm. The text the start
/// signs, `None` when there is nothing to say.
///
/// Lot 345 (the re-check of #550, N3): `previous` is the PROFILE the chain's
/// last `agent_boot` signed (`nn_evidence`'s `previous_boot_profile`), no
/// longer whether it enforced: one boot of the enforcing profile under a
/// detect-only drop-in observed, and the downgrade after it went unsaid.
pub fn unsigned_downgrade(previous: Option<&str>, now: &ResolvedProfile) -> Option<String> {
    (previous == Some(Profile::Enforcing.as_str())
        && now.profile.observe_only()
        && now.source != ProfileSource::Overlay)
        .then(|| {
            format!(
                "the response profile is {} after a run of the enforcing profile, and no \
                 signed profile.local asked for it: a switch to alpha is a signed `nn-admin \
                 config overlay set profile` — check who removed the overlay or edited the \
                 install manifest",
                now.describe()
            )
        })
}

/// The review of #553 (F2): the alarm of a start while an unsigned
/// downgrade the chain holds (signed at `pending_since`,
/// `nn_evidence`'s `profile_downgrade_pending`) is still unanswered — the
/// profile now is not from a verified `profile.local`. One reboot after the
/// downgrade, [`unsigned_downgrade`] compared to the boot that alarmed (it
/// ran alpha) and said nothing: the alarm, the status' degradation and the
/// trust level were laundered. A signed `profile.local` (its start) or a
/// signed `nn-admin config overlay set profile` answers it; an unsigned
/// return to enforcing does not (the downgrade happened, and no key saw it).
pub fn pending_downgrade(pending_since: Option<&str>, now: &ResolvedProfile) -> Option<String> {
    let since = pending_since?;
    (now.source != ProfileSource::Overlay).then(|| {
        format!(
            "an unsigned downgrade of the response profile (signed in the audit chain at {since}) \
             is not acknowledged: the profile is {} now, and no signed profile.local has been run \
             since — acknowledge it with a signed `nn-admin config overlay set profile` (alpha or \
             enforcing), after checking who removed the overlay or edited the install manifest",
            now.describe()
        )
    })
}

/// Lot 345 (the re-check of #550, N3b): the source the start keeps an
/// unsigned downgrade under in the agent's degradations — what `nn-admin
/// status --key` lists, and what lowers the trust level.
pub const DOWNGRADE_SOURCE: &str = "profile";

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

    /// Named (lot 341, the review of #550 F8): an `alpha` start after an
    /// enforcing run is an alarm unless a signed `profile.local` asked for
    /// it; a first boot, an alpha run before, an enforcing start are none.
    #[test]
    fn an_unsigned_downgrade_to_alpha_is_an_alarm() {
        let manifest_alpha = resolve(None, Some(Profile::Alpha));
        let overlay_alpha = resolve(Some(Profile::Alpha), Some(Profile::Enforcing));
        let enforcing = resolve(None, Some(Profile::Enforcing));
        let text = unsigned_downgrade(Some("enforcing"), &manifest_alpha).expect("an alarm");
        assert!(text.contains("alpha (install manifest)"), "{text}");
        assert_eq!(unsigned_downgrade(Some("enforcing"), &overlay_alpha), None);
        assert_eq!(unsigned_downgrade(Some("alpha"), &manifest_alpha), None);
        assert_eq!(unsigned_downgrade(None, &manifest_alpha), None);
        assert_eq!(unsigned_downgrade(Some("enforcing"), &enforcing), None);
    }

    /// Named (lot 345; the re-check of #550, N3a): the chain of the review —
    /// a boot of the enforcing profile, one boot of it under a detect-only
    /// drop-in (it observed: no profile changed, no alarm), then the
    /// manifest edited to `alpha` — alarms at the third boot: the boot before
    /// it signed the profile `enforcing`. Compared on `detect_only`, the
    /// observing boot in between laundered it.
    #[test]
    fn an_observing_boot_between_does_not_launder_the_downgrade() {
        let manifest_alpha = resolve(None, Some(Profile::Alpha));
        let enforcing = resolve(None, Some(Profile::Enforcing));
        // boot 2: the enforcing profile again (its gate on by the drop-in)
        assert_eq!(unsigned_downgrade(Some("enforcing"), &enforcing), None);
        // boot 3: the chain's last boot signed `enforcing`, observing or not
        let text = unsigned_downgrade(Some(enforcing.profile.as_str()), &manifest_alpha)
            .expect("the downgrade is said");
        assert!(
            text.contains("after a run of the enforcing profile"),
            "{text}"
        );
        // an unknown previous profile (an observing boot before the field)
        assert_eq!(unsigned_downgrade(None, &manifest_alpha), None);
    }

    /// Named (the review of #553, F2): the chain of the review — boot 1
    /// enforcing, boot 2 alpha from the manifest (alarm, signed), boot 3 and
    /// boot 4 alpha again — still alarms at boots 3 and 4: the downgrade the
    /// chain holds is pending until something signed answers it. A start
    /// from a signed profile.local answers it; an unsigned enforcing start
    /// does not.
    #[test]
    fn a_pending_downgrade_alarms_at_every_start_until_signed() {
        let manifest_alpha = resolve(None, Some(Profile::Alpha));
        let overlay_alpha = resolve(Some(Profile::Alpha), Some(Profile::Enforcing));
        let overlay_enforcing = resolve(Some(Profile::Enforcing), Some(Profile::Alpha));
        let manifest_enforcing = resolve(None, Some(Profile::Enforcing));
        let since = Some("2026-11-14T10:00:00Z");
        // boots 3 and 4: the previous boot ran alpha — no new downgrade …
        assert_eq!(unsigned_downgrade(Some("alpha"), &manifest_alpha), None);
        // … but the chain's is pending
        let text = pending_downgrade(since, &manifest_alpha).expect("still an alarm");
        assert!(text.contains("2026-11-14T10:00:00Z"), "{text}");
        assert!(text.contains("alpha (install manifest)"), "{text}");
        assert!(text.contains("nn-admin config overlay set profile"), "{text}");
        assert!(pending_downgrade(since, &manifest_enforcing).is_some());
        // a signed profile.local answers it, either way
        assert_eq!(pending_downgrade(since, &overlay_alpha), None);
        assert_eq!(pending_downgrade(since, &overlay_enforcing), None);
        // nothing pending
        assert_eq!(pending_downgrade(None, &manifest_alpha), None);
        assert_eq!(ProfileSource::Overlay.label(), "signed profile.local");
    }

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
