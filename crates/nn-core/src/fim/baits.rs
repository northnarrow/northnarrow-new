//! The anti-tamper baits: each path with its inert template (Tappa 9.5.1;
//! the agent's `fim::honeypot`, which deploys them and sweeps them at boot).
//!
//! R08b (lab PR 251): cut verbatim from the agent's `fim::honeypot`, which
//! re-exports it, because NN-L-FIM-024 (`fim::rules`, moving to nn-core
//! with the engine) watches these paths ([`BAIT_PATHS`]): content, as the
//! canary templates of R07 (lab PR 247). The templates are embedded from
//! `configs/honeypot-baits/` (`NN_REPO_ROOT`), so the agent's recreate holds
//! what `deploy/install.sh` writes.

macro_rules! bait {
    ($name:literal) => {
        include_str!(concat!(
            env!("NN_REPO_ROOT"),
            "/configs/honeypot-baits/",
            $name
        ))
    };
}

/// The baits: each path with its template, embedded from
/// `configs/honeypot-baits/`. External audit NN-AUD-289 (FIMR-015): the
/// paths were a list in `fim::rules` and the contents a `match` here,
/// paired only by a test, and the sweep took a bait without a template
/// for a bug — `.expect`, a panic (`panic = "abort"`: the agent). One
/// table now: a bait cannot be listed without its content.
pub const BAITS: &[(&str, &str)] = &[
    ("/etc/northnarrow/agent.dev.lock", bait!("agent.dev.lock")),
    (
        "/etc/northnarrow/kill_switch.conf",
        bait!("kill_switch.conf"),
    ),
    (
        "/etc/northnarrow/maintenance.mode",
        bait!("maintenance.mode"),
    ),
    (
        "/etc/northnarrow/debug_disable.flag",
        bait!("debug_disable.flag"),
    ),
    (
        "/etc/northnarrow/agent.legacy.conf",
        bait!("agent.legacy.conf"),
    ),
    (
        "/var/lib/northnarrow/shutdown.signal",
        bait!("shutdown.signal"),
    ),
    ("/var/lib/northnarrow/disable.token", bait!("disable.token")),
    (
        "/var/lib/northnarrow/override.config",
        bait!("override.config"),
    ),
    ("/run/northnarrow/pause.flag", bait!("pause.flag")),
    ("/run/northnarrow/unload.signal", bait!("unload.signal")),
];

/// The paths of [`BAITS`], in its order: what
/// [`crate::fim::rules::HONEYPOT_PATHS`] is.
pub const BAIT_PATHS: [&str; BAITS.len()] = {
    let mut paths = [""; BAITS.len()];
    let mut i = 0;
    while i < BAITS.len() {
        paths[i] = BAITS[i].0;
        i += 1;
    }
    paths
};

/// The template of a bait (its `last_modified=` line empty), embedded from
/// `configs/honeypot-baits/`. `None` for any path not in [`BAITS`].
pub fn bait_content(path: &str) -> Option<&'static str> {
    BAITS
        .iter()
        .find(|(p, _)| *p == path)
        .map(|(_, content)| *content)
}
